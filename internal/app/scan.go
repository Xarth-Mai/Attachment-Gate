package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	securezip "github.com/Xarth-Mai/Attachment-Gate/internal/archive"
	"github.com/Xarth-Mai/Attachment-Gate/internal/batch"
	"github.com/Xarth-Mai/Attachment-Gate/internal/config"
	"github.com/Xarth-Mai/Attachment-Gate/internal/detect"
	"github.com/Xarth-Mai/Attachment-Gate/internal/malware"
	"github.com/Xarth-Mai/Attachment-Gate/internal/manifest"
	"github.com/Xarth-Mai/Attachment-Gate/internal/output"
)

const maxConfigBytes = 1 << 20

type ScanOptions struct {
	Input      string
	Output     string
	ConfigPath string
	Verbose    io.Writer
}

type PolicyIdentity struct {
	ToolVersion string `json:"tool_version"`
	Profile     struct {
		Name    string `json:"name"`
		Version int    `json:"version"`
	} `json:"profile"`
	EffectiveConfigSHA256 string `json:"effective_config_sha256"`
}

func DescribePolicy(configPath, toolVersion string) (PolicyIdentity, error) {
	cfg, _, err := loadConfig(configPath)
	if err != nil {
		return PolicyIdentity{}, exitError(ExitUsage, "invalid configuration: %v", err)
	}
	identity := PolicyIdentity{ToolVersion: toolVersion, EffectiveConfigSHA256: effectiveConfigHash(cfg)}
	identity.Profile.Name = cfg.Profile.Name
	identity.Profile.Version = cfg.Profile.Version
	return identity, nil
}

type scanner struct {
	cfg            *config.Config
	detector       detect.Detector
	clamd          *malware.Client
	staging        *output.Staging
	allowed        map[string]bool
	files          []manifest.File
	verbose        io.Writer
	nextID         int
	inputFiles     int
	archiveFiles   int
	extractedBytes int64
	fileStarted    time.Time
}

func Scan(ctx context.Context, options ScanOptions) error {
	started := time.Now()
	verbosef(options.Verbose, "stage=config")
	cfg, _, err := loadConfig(options.ConfigPath)
	if err != nil {
		return exitError(ExitUsage, "invalid configuration: %v", err)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Limits.BatchTimeout.Std())
	defer cancel()

	verbosef(options.Verbose, "stage=input")
	input, err := batch.LoadContext(ctx, options.Input, cfg)
	if err != nil {
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		return exitError(ExitInput, "invalid input batch")
	}
	if len(input.Files) > cfg.Limits.MaxDiscoveredFiles {
		return exitError(ExitInput, "invalid input batch: discovered file limit exceeded")
	}
	if err := validateOutputPath(options.Output, cfg.Roots.Results, input.BatchID); err != nil {
		return exitError(ExitUsage, "invalid output path: %v", err)
	}

	verbosef(options.Verbose, "stage=dependencies")
	detector := detectorForConfig(cfg)
	detectorVersion, clamd, malwareEngine, err := checkDependencies(ctx, cfg, detector)
	if err != nil {
		verbosef(options.Verbose, "stage=dependencies status=failed error=%s", err)
		return dependencyError(ctx, err)
	}
	staging, err := output.New(options.Output)
	if err != nil {
		return exitError(ExitFilesystem, "cannot create output staging directory")
	}
	defer staging.Abort()

	s := scanner{
		cfg:        cfg,
		detector:   detector,
		clamd:      clamd,
		staging:    staging,
		verbose:    options.Verbose,
		allowed:    make(map[string]bool, len(cfg.AllowedTypes)),
		files:      make([]manifest.File, 0, len(input.Files)),
		inputFiles: len(input.Files),
	}
	for _, kind := range cfg.AllowedTypes {
		s.allowed[kind] = true
	}
	verbosef(options.Verbose, "stage=scan")
	for index := range input.Files {
		if err := contextFailure(ctx); err != nil {
			return err
		}
		file := &input.Files[index]
		name := outputName(file.OriginalName, 200)
		record := s.newFile(nil, file.AttachmentID, file.OriginalName, "upload", "file", file.Size, file.SHA256, file.OriginalName)
		if file.Size > int64(s.cfg.Limits.MaxInputFileSize) {
			s.reject(&record, "file_too_large")
			continue
		}
		if reason := excludedPath(name, nil, s.cfg.Paths.ExcludeFileNames, s.cfg.Paths.ExcludeExtensions); reason != "" {
			s.reject(&record, reason)
			continue
		}
		snapshot, err := snapshotInput(ctx, staging.Path, file, index)
		if err != nil {
			return err
		}
		processErr := s.processUpload(ctx, file, snapshot, index, len(input.Files), name, record)
		removeErr := os.Remove(snapshot)
		if processErr != nil {
			return processErr
		}
		if removeErr != nil {
			return exitError(ExitFilesystem, "cannot remove input snapshot")
		}
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}

	finished := time.Now()
	verbosef(options.Verbose, "stage=manifest")
	m := manifest.Manifest{
		SchemaVersion: manifest.SchemaVersion,
		ScanID:        newScanID(),
		BatchID:       input.BatchID,
		Status:        "completed",
		StartedAt:     started,
		FinishedAt:    finished,
		Policy: manifest.Policy{
			Name:    cfg.Profile.Name,
			Version: cfg.Profile.Version,
			SHA256:  effectiveConfigHash(cfg),
		},
		Engines: manifest.Engines{
			TypeDetector: manifest.Engine{Name: "libmagic", Version: firstLine(detectorVersion)},
			Malware:      malwareEngine,
		},
		Files: s.files,
	}
	m.Summary, m.Outcome = summarize(s.files)
	data, err := manifest.Marshal(m)
	if err != nil {
		return exitError(ExitInternal, "cannot encode result manifest")
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}
	if err := staging.WriteManifest(data); err != nil {
		return exitError(ExitFilesystem, "cannot write result manifest")
	}
	if err := contextFailure(ctx); err != nil {
		return err
	}
	verbosef(options.Verbose, "stage=publish")
	if err := staging.PublishContext(ctx, cfg.Output.FileMode.FileMode(), cfg.Output.DirectoryMode.FileMode()); err != nil {
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		return exitError(ExitFilesystem, "cannot publish result")
	}
	return nil
}

func (s *scanner) processUpload(ctx context.Context, file *batch.File, scanPath string, index, total int, name string, record manifest.File) error {
	result, err := s.detect(ctx, scanPath, file.OriginalName)
	record.Detected = detected(result)
	if result.Type == detect.TypeArchiveZIP {
		record.Kind = "container"
	}
	if err != nil {
		return s.detectorFailure(ctx, &record, err)
	}
	if result.Type == detect.TypeArchiveZIP {
		return s.processArchive(ctx, file, scanPath, index, total, name, result, record)
	}
	if unsupportedArchiveMIME(result.MIME) {
		record.Warnings = append(record.Warnings, manifest.Warning{Code: "archive_unsupported", DeclaredExtension: result.Extension})
	}
	if s.cfg.Policy.Executable == "reject" && isExecutableType(result.Type) {
		s.reject(&record, "executable_not_allowed")
		return nil
	}
	if isExecutableType(result.Type) {
		record.Warnings = append(record.Warnings, manifest.Warning{Code: "executable_found", DeclaredExtension: result.Extension})
	} else if warning := warningFor(result, s.allowed); warning != nil {
		record.Warnings = append(record.Warnings, *warning)
	}
	if s.applyExtensionPolicy(&record, result) {
		return nil
	}
	var documentLimits securezip.Limits
	if isOOXML(result.Type) {
		limits, _, valid, err := s.preflightContainer(ctx, scanPath, &record, false)
		if err != nil || !valid {
			return err
		}
		documentLimits = limits
	}
	if reason, err := s.scanMalware(ctx, scanPath); err != nil {
		return err
	} else if reason != "" {
		s.reject(&record, reason)
		return nil
	}
	if isOOXML(result.Type) {
		valid, err := s.validateOOXML(ctx, scanPath, documentLimits, &record)
		if err != nil {
			return err
		}
		if !valid {
			return nil
		}
	}

	rel := numberedName(index, total, name)
	digest, size, err := s.staging.CopyContext(ctx, scanPath, rel)
	if err != nil {
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		return exitError(ExitFilesystem, "cannot copy approved file")
	}
	if size != file.Size || digest != file.SHA256 {
		return exitError(ExitInput, "input blob changed during scanning")
	}
	s.approve(&record, rel, "copied")
	return nil
}

func (s *scanner) processArchive(ctx context.Context, file *batch.File, scanPath string, index, total int, name string, result detect.Result, record manifest.File) error {
	if !s.cfg.Archives.Enabled || !s.allowed[string(detect.TypeArchiveZIP)] {
		s.reject(&record, "archive_unsupported")
		return nil
	}
	if s.applyExtensionPolicy(&record, result) {
		return nil
	}
	limits, preflightStats, valid, err := s.preflightContainer(ctx, scanPath, &record, true)
	if err != nil || !valid {
		return err
	}
	if reason, err := s.scanMalware(ctx, scanPath); err != nil {
		return err
	} else if reason != "" {
		s.reject(&record, reason)
		return nil
	}

	work := filepath.Join(s.staging.Path, ".work-"+record.ID)
	paths, stats, err := securezip.Extract(ctx, scanPath, work, limits)
	s.extractedBytes += stats.ExtractedBytes
	if err != nil {
		return s.archiveFailure(ctx, &record, err)
	}
	s.archiveFiles += preflightStats.Files

	directory := numberedName(index, total, archiveDirectory(name))
	if err := s.staging.Mkdir(directory); err != nil {
		return exitError(ExitFilesystem, "cannot create approved archive directory")
	}
	s.approve(&record, directory, "expanded")
	parentID := record.ID
	type member struct {
		path     string
		rejected *securezip.RejectedEntry
	}
	members := make([]member, 0, len(paths)+len(stats.Rejected))
	for _, relative := range paths {
		members = append(members, member{path: relative})
	}
	for index := range stats.Rejected {
		members = append(members, member{path: stats.Rejected[index].Path, rejected: &stats.Rejected[index]})
	}
	slices.SortFunc(members, func(a, b member) int { return strings.Compare(a.path, b.path) })
	for _, member := range members {
		if err := contextFailure(ctx); err != nil {
			return err
		}
		if member.rejected != nil {
			s.rejectArchiveEntry(*member.rejected, file.OriginalName, file.AttachmentID, &parentID)
			continue
		}
		physical := filepath.Join(work, filepath.FromSlash(member.path))
		sourcePath := stats.SourcePaths[member.path]
		if sourcePath == "" {
			sourcePath = member.path
		}
		if err := s.processArchiveFile(ctx, physical, sourcePath, member.path, file.OriginalName, directory, file.AttachmentID, &parentID); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(work); err != nil {
		return exitError(ExitFilesystem, "cannot remove archive staging directory")
	}
	return nil
}

func (s *scanner) validateOOXML(ctx context.Context, filePath string, limits securezip.Limits, record *manifest.File) (bool, error) {
	work := filepath.Join(s.staging.Path, ".work-"+record.ID)
	_, stats, err := securezip.Extract(ctx, filePath, work, limits)
	s.extractedBytes += stats.ExtractedBytes
	if err != nil {
		if fatal := s.archiveFailure(ctx, record, err); fatal != nil {
			return false, fatal
		}
		return false, nil
	}
	if len(stats.Rejected) != 0 {
		if err := os.RemoveAll(work); err != nil {
			return false, exitError(ExitFilesystem, "cannot remove document validation directory")
		}
		s.reject(record, string(stats.Rejected[0].Code))
		return false, nil
	}
	if err := os.RemoveAll(work); err != nil {
		return false, exitError(ExitFilesystem, "cannot remove document validation directory")
	}
	return true, nil
}

func (s *scanner) preflightContainer(ctx context.Context, filePath string, record *manifest.File, countDiscovered bool) (securezip.Limits, securezip.Stats, bool, error) {
	limits, ok := s.extractionLimits()
	if !ok {
		s.reject(record, "archive_limit_exceeded")
		return securezip.Limits{}, securezip.Stats{}, false, nil
	}
	stats, err := securezip.Preflight(ctx, filePath, limits)
	if err != nil {
		if fatal := s.archiveFailure(ctx, record, err); fatal != nil {
			return securezip.Limits{}, securezip.Stats{}, false, fatal
		}
		return securezip.Limits{}, securezip.Stats{}, false, nil
	}
	if countDiscovered && stats.Files > s.cfg.Limits.MaxDiscoveredFiles-s.inputFiles-s.archiveFiles {
		s.reject(record, "archive_limit_exceeded")
		return securezip.Limits{}, securezip.Stats{}, false, nil
	}
	return limits, stats, true, nil
}

func (s *scanner) extractionLimits() (securezip.Limits, bool) {
	remainingBytes := int64(s.cfg.Limits.MaxExtractedTotalSize) - s.extractedBytes
	if remainingBytes <= 0 {
		return securezip.Limits{}, false
	}
	return configuredArchiveLimits(s.cfg, s.cfg.Limits.MaxArchiveEntries, remainingBytes), true
}

func isOOXML(kind detect.Type) bool {
	return kind == detect.TypeDocumentDOCX || kind == detect.TypeDocumentXLSX || kind == detect.TypeDocumentPPTX
}

func detectorForConfig(cfg *config.Config) detect.Detector {
	return detect.Detector{
		MaxImagePixels: cfg.Limits.MaxImagePixels,
		ArchiveLimits: configuredArchiveLimits(
			cfg,
			cfg.Limits.MaxArchiveEntries,
			int64(cfg.Limits.MaxExtractedTotalSize),
		),
	}
}

func configuredArchiveLimits(cfg *config.Config, maxEntries int, maxBytes int64) securezip.Limits {
	return securezip.Limits{
		MaxEntries:          maxEntries,
		MaxDeclaredBytes:    maxBytes,
		MaxFileBytes:        int64(cfg.Limits.MaxExtractedFileSize),
		MaxTotalBytes:       maxBytes,
		MaxCompressionRatio: cfg.Limits.MaxCompressionRatio,
		MaxPathDepth:        cfg.Limits.MaxPathDepth,
		MaxPathBytes:        cfg.Limits.MaxRelativePathBytes,
	}
}

func (s *scanner) processArchiveFile(ctx context.Context, physical, sourceRelative, outputRelative, containerName, outputDirectory, attachmentID string, parentID *string) error {
	digest, size, err := hashFile(ctx, physical)
	if err != nil {
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		return exitError(ExitFilesystem, "cannot read extracted file")
	}
	source := containerName + "!" + sourceRelative
	record := s.newFile(parentID, attachmentID, source, "archive", "file", size, digest, outputRelative)
	if reason := excludedPath(outputRelative, s.cfg.Paths.ExcludeDirectoryNames, s.cfg.Paths.ExcludeFileNames, s.cfg.Paths.ExcludeExtensions); reason != "" {
		s.reject(&record, reason)
		return nil
	}

	result, err := s.detect(ctx, physical, outputRelative)
	record.Detected = detected(result)
	if err != nil {
		return s.detectorFailure(ctx, &record, err)
	}
	if nestedArchive(result) {
		record.Warnings = append(record.Warnings, manifest.Warning{Code: "nested_archive_not_allowed", DeclaredExtension: result.Extension})
	} else if result.Type == detect.TypeArchiveZIP {
		record.Kind = "container"
	}
	if s.cfg.Policy.Executable == "reject" && isExecutableType(result.Type) {
		s.reject(&record, "executable_not_allowed")
		return nil
	}
	if isExecutableType(result.Type) {
		record.Warnings = append(record.Warnings, manifest.Warning{Code: "executable_found", DeclaredExtension: result.Extension})
	} else if warning := warningFor(result, s.allowed); warning != nil {
		record.Warnings = append(record.Warnings, *warning)
	}
	if s.applyExtensionPolicy(&record, result) {
		return nil
	}
	var documentLimits securezip.Limits
	if isOOXML(result.Type) {
		limits, _, valid, err := s.preflightContainer(ctx, physical, &record, false)
		if err != nil || !valid {
			return err
		}
		documentLimits = limits
	}
	if reason, err := s.scanMalware(ctx, physical); err != nil {
		return err
	} else if reason != "" {
		s.reject(&record, reason)
		return nil
	}
	if isOOXML(result.Type) {
		valid, err := s.validateOOXML(ctx, physical, documentLimits, &record)
		if err != nil || !valid {
			return err
		}
	}

	rel := path.Join(outputDirectory, outputRelative)
	copiedDigest, copiedSize, err := s.staging.CopyContext(ctx, physical, rel)
	if err != nil {
		if ctx.Err() != nil {
			return contextFailure(ctx)
		}
		return exitError(ExitFilesystem, "cannot copy approved archive entry")
	}
	if copiedSize != size || copiedDigest != digest {
		return exitError(ExitFilesystem, "extracted file changed during scanning")
	}
	s.approve(&record, rel, "copied")
	return nil
}

func (s *scanner) rejectArchiveEntry(entry securezip.RejectedEntry, containerName, attachmentID string, parentID *string) {
	sourcePath := entry.SourcePath
	if sourcePath == "" {
		sourcePath = entry.Path
	}
	record := s.newFile(parentID, attachmentID, containerName+"!"+sourcePath, "archive", "file", entry.Size, entry.SHA256, entry.Path)
	s.reject(&record, string(entry.Code))
}

func (s *scanner) detect(ctx context.Context, physical, logical string) (detect.Result, error) {
	fileCtx, cancel := context.WithTimeout(ctx, s.cfg.Limits.FileScanTimeout.Std())
	defer cancel()
	return s.detector.DetectAs(fileCtx, physical, logical)
}

func (s *scanner) detectorFailure(ctx context.Context, record *manifest.File, err error) error {
	if ctx.Err() != nil {
		return contextFailure(ctx)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		if s.cfg.Policy.DetectorError == "reject_batch" {
			return exitError(ExitCanceled, "file type detector timed out")
		}
		s.reject(record, "type_detector_error")
		return nil
	}
	if code := securezip.ErrorCode(err); code != "" {
		switch code {
		case securezip.CodeCanceled:
			if s.cfg.Policy.DetectorError == "reject_batch" {
				return exitError(ExitCanceled, "file type detector timed out")
			}
			s.reject(record, "type_detector_error")
			return nil
		case securezip.CodeInvalidLimits:
			return exitError(ExitInternal, "invalid archive limits")
		default:
			s.reject(record, string(code))
			return nil
		}
	}
	if s.cfg.Policy.DetectorError == "reject_batch" {
		return exitError(ExitDependency, "file type detector failed")
	}
	code := "type_detector_error"
	if errors.Is(err, detect.ErrImageDimensionsExceeded) {
		code = "image_dimensions_exceeded"
	}
	s.reject(record, code)
	return nil
}

func (s *scanner) scanMalware(ctx context.Context, filePath string) (string, error) {
	if s.clamd == nil {
		return "", exitError(ExitDependency, "malware scanner is unavailable")
	}
	file, err := os.Open(filePath)
	if err != nil {
		return "", exitError(ExitFilesystem, "cannot open file for malware scan")
	}
	defer file.Close()
	fileCtx, cancel := context.WithTimeout(ctx, s.cfg.Limits.FileScanTimeout.Std())
	defer cancel()
	result, err := s.clamd.Scan(fileCtx, file)
	if err != nil {
		if ctx.Err() != nil {
			return "", contextFailure(ctx)
		}
		code := "malware_scan_error"
		if errors.Is(fileCtx.Err(), context.DeadlineExceeded) {
			code = "malware_scan_timeout"
		}
		if s.cfg.Policy.MalwareScanError == "reject_batch" {
			if code == "malware_scan_timeout" {
				return "", exitError(ExitCanceled, "malware scan timed out")
			}
			return "", exitError(ExitDependency, "malware scanner failed")
		}
		return code, nil
	}
	switch result.Status {
	case malware.StatusOK:
		return "", nil
	case malware.StatusFound:
		return "malware_found", nil
	case malware.StatusError:
		if s.cfg.Policy.MalwareScanError == "reject_batch" && !strings.Contains(strings.ToLower(result.Message), "instream size limit exceeded") {
			return "", exitError(ExitDependency, "malware scanner failed")
		}
		return "malware_scan_error", nil
	default:
		return "", exitError(ExitDependency, "malware scanner returned an invalid response")
	}
}

func (s *scanner) archiveFailure(ctx context.Context, record *manifest.File, err error) error {
	code := securezip.ErrorCode(err)
	switch code {
	case securezip.CodeCanceled:
		return contextFailure(ctx)
	case securezip.CodeIO:
		return exitError(ExitFilesystem, "archive staging failed")
	case securezip.CodeInvalidLimits:
		return exitError(ExitInternal, "invalid archive limits")
	case "":
		return exitError(ExitInternal, "archive processing failed")
	default:
		s.reject(record, string(code))
		return nil
	}
}

func (s *scanner) applyExtensionPolicy(record *manifest.File, result detect.Result) bool {
	warning := extensionWarning(result)
	if warning == nil {
		return false
	}
	record.Warnings = append(record.Warnings, *warning)
	if s.cfg.Policy.ExtensionMismatch == "reject" {
		s.reject(record, "extension_mismatch")
		return true
	}
	return false
}

func (s *scanner) newFile(parentID *string, attachmentID, source, origin, kind string, size int64, digest, logicalName string) manifest.File {
	s.nextID++
	s.fileStarted = time.Now()
	return manifest.File{
		ID:           fmt.Sprintf("f_%04d", s.nextID),
		ParentID:     parentID,
		AttachmentID: attachmentID,
		SourcePath:   source,
		Origin:       origin,
		Kind:         kind,
		Size:         size,
		SHA256:       digest,
		Detected: manifest.Detected{
			Type:      string(detect.TypeUnknownBinary),
			Extension: strings.ToLower(path.Ext(logicalName)),
		},
		Decision: "rejected",
		Action:   "omitted",
		Warnings: []manifest.Warning{},
	}
}

func (s *scanner) reject(record *manifest.File, code string) {
	record.Decision = "rejected"
	record.Action = "omitted"
	record.OutputPath = nil
	record.Reason = &manifest.Reason{Code: code}
	s.files = append(s.files, *record)
	s.logf("%s detected=%s decision=rejected reason=%s duration=%s", record.ID, record.Detected.Type, code, time.Since(s.fileStarted).Round(time.Millisecond))
}

func (s *scanner) approve(record *manifest.File, outputPath, action string) {
	record.Decision = "approved"
	record.Action = action
	record.OutputPath = &outputPath
	record.Reason = nil
	s.files = append(s.files, *record)
	s.logf("%s detected=%s decision=approved duration=%s", record.ID, record.Detected.Type, time.Since(s.fileStarted).Round(time.Millisecond))
}

func (s *scanner) logf(format string, args ...any) {
	verbosef(s.verbose, format, args...)
}

func verbosef(writer io.Writer, format string, args ...any) {
	if writer != nil {
		_, _ = fmt.Fprintf(writer, format+"\n", args...)
	}
}

func loadConfig(filePath string) (*config.Config, []byte, error) {
	if filePath == "" {
		return nil, nil, errors.New("--config is required")
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, errors.New("cannot read config")
	}
	if len(data) > maxConfigBytes {
		return nil, nil, errors.New("config is too large")
	}
	cfg, err := config.Parse(data)
	return cfg, data, err
}

func validateOutputPath(result, root, batchID string) error {
	if !filepath.IsAbs(result) || filepath.Clean(result) != result || filepath.Dir(result) != root || filepath.Base(result) != batchID {
		return errors.New("output must be the matching direct child of the configured results root")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("results root is not a real directory")
	}
	return nil
}

func checkDependencies(ctx context.Context, cfg *config.Config, detector detect.Detector) (string, *malware.Client, *manifest.MalwareEngine, error) {
	fileCtx, cancel := context.WithTimeout(ctx, cfg.Limits.FileScanTimeout.Std())
	if err := detect.CheckImageDecoders(fileCtx, cfg.AllowedTypes); err != nil {
		cancel()
		return "", nil, nil, err
	}
	version, err := detector.Version(fileCtx)
	if err != nil {
		cancel()
		return "", nil, nil, errors.New("file/libmagic is unavailable")
	}
	probe, err := os.CreateTemp("", ".attachment-gate-magic-")
	if err != nil {
		cancel()
		return "", nil, nil, errors.New("cannot create type detector probe")
	}
	probeName := probe.Name()
	if _, err = probe.WriteString("attachment gate type probe\n"); err == nil {
		err = probe.Close()
	} else {
		_ = probe.Close()
	}
	if err == nil {
		_, err = detector.DetectAs(fileCtx, probeName, "probe.txt")
	}
	_ = os.Remove(probeName)
	cancel()
	if err != nil {
		return "", nil, nil, errors.New("file/libmagic database is unavailable")
	}
	if !cfg.Malware.Enabled || !cfg.Malware.Required {
		return "", nil, nil, errors.New("malware scanner is required")
	}
	client, err := malware.New(cfg.Malware.Socket)
	if err != nil {
		return "", nil, nil, errors.New("invalid malware scanner configuration")
	}
	clamCtx, cancel := context.WithTimeout(ctx, cfg.Limits.FileScanTimeout.Std())
	defer cancel()
	if err := client.Ping(clamCtx); err != nil {
		return "", nil, nil, errors.New("malware scanner is unavailable")
	}
	rawVersion, err := client.Version(clamCtx)
	if err != nil {
		return "", nil, nil, errors.New("malware scanner version is unavailable")
	}
	engine, database, databaseTime, parsedTime, err := parseClamVersion(rawVersion)
	if err != nil {
		return "", nil, nil, errors.New("malware scanner returned an invalid version")
	}
	now := time.Now()
	if parsedTime.After(now.Add(24*time.Hour)) || now.Sub(parsedTime) > cfg.Malware.MaxDatabaseAge.Std() {
		return "", nil, nil, errors.New("malware signature database is stale")
	}
	return version, client, &manifest.MalwareEngine{
		Name:            "clamav",
		EngineVersion:   engine,
		DatabaseVersion: database,
		DatabaseTime:    databaseTime,
	}, nil
}

func parseClamVersion(value string) (engine, database, databaseTime string, parsedTime time.Time, err error) {
	parts := strings.SplitN(value, "/", 3)
	if len(parts) != 3 {
		return "", "", "", time.Time{}, errors.New("unexpected version format")
	}
	engine = strings.TrimSpace(strings.TrimPrefix(parts[0], "ClamAV "))
	database = strings.TrimSpace(parts[1])
	databaseTime = strings.TrimSpace(parts[2])
	if engine == "" || database == "" || databaseTime == "" {
		return "", "", "", time.Time{}, errors.New("incomplete version")
	}
	for _, layout := range []string{"Mon Jan _2 15:04:05 2006", time.RFC3339} {
		parsedTime, err = time.ParseInLocation(layout, databaseTime, time.Local)
		if err == nil {
			return engine, database, databaseTime, parsedTime, nil
		}
	}
	return "", "", "", time.Time{}, err
}

func summarize(files []manifest.File) (manifest.Summary, string) {
	summary := manifest.Summary{DiscoveredFiles: len(files)}
	for _, file := range files {
		if file.Origin == "upload" {
			summary.UploadedFiles++
		}
		if file.Decision == "approved" {
			summary.ApprovedFiles++
			summary.ApprovedBytes += file.Size
		} else {
			summary.RejectedFiles++
		}
	}
	switch {
	case summary.ApprovedFiles == 0:
		return summary, "none_approved"
	case summary.RejectedFiles == 0:
		return summary, "all_approved"
	default:
		return summary, "partial"
	}
}

func detected(result detect.Result) manifest.Detected {
	return manifest.Detected{Type: string(result.Type), MIME: result.MIME, Extension: result.Extension}
}

func numberedName(index, total int, name string) string {
	width := max(2, len(strconv.Itoa(total)))
	return fmt.Sprintf("%0*d-%s", width, index+1, name)
}

func snapshotInput(ctx context.Context, stagingPath string, file *batch.File, index int) (string, error) {
	before, err := os.Lstat(file.Path)
	if err != nil || !before.Mode().IsRegular() {
		return "", exitError(ExitInput, "input blob changed before scanning")
	}
	source, err := os.Open(file.Path)
	if err != nil {
		return "", exitError(ExitInput, "input blob changed before scanning")
	}
	after, statErr := source.Stat()
	if statErr != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = source.Close()
		return "", exitError(ExitInput, "input blob changed before scanning")
	}
	destination := filepath.Join(stagingPath, fmt.Sprintf(".input-%04d", index+1))
	snapshot, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = source.Close()
		return "", exitError(ExitFilesystem, "cannot create input snapshot")
	}
	h := sha256.New()
	reader := io.LimitReader(source, file.Size+1)
	n, copyErr := io.Copy(io.MultiWriter(snapshot, h), contextReader{ctx: ctx, reader: reader})
	syncErr := snapshot.Sync()
	closeErr := errors.Join(source.Close(), snapshot.Close())
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(destination)
		if ctx.Err() != nil {
			return "", contextFailure(ctx)
		}
		return "", exitError(ExitFilesystem, "cannot create input snapshot")
	}
	if n != file.Size || hex.EncodeToString(h.Sum(nil)) != file.SHA256 {
		_ = os.Remove(destination)
		return "", exitError(ExitInput, "input blob changed before scanning")
	}
	return destination, nil
}

func hashFile(ctx context.Context, filePath string) (string, int64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, contextReader{ctx: ctx, reader: f})
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(buffer)
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func effectiveConfigHash(cfg *config.Config) string {
	canonical := *cfg
	canonical.AllowedTypes = slices.Clone(cfg.AllowedTypes)
	canonical.Archives.AllowedFormats = slices.Clone(cfg.Archives.AllowedFormats)
	canonical.Paths.ExcludeDirectoryNames = slices.Clone(cfg.Paths.ExcludeDirectoryNames)
	canonical.Paths.ExcludeFileNames = slices.Clone(cfg.Paths.ExcludeFileNames)
	canonical.Paths.ExcludeExtensions = slices.Clone(cfg.Paths.ExcludeExtensions)
	slices.Sort(canonical.AllowedTypes)
	slices.Sort(canonical.Archives.AllowedFormats)
	slices.Sort(canonical.Paths.ExcludeDirectoryNames)
	slices.Sort(canonical.Paths.ExcludeFileNames)
	slices.Sort(canonical.Paths.ExcludeExtensions)
	data, _ := json.Marshal(canonical)
	return sha256Hex(data)
}

func newScanID() string {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(id[:])
}

func firstLine(value string) string {
	line, _, _ := strings.Cut(value, "\n")
	return strings.TrimSpace(line)
}

func dependencyError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return contextFailure(ctx)
	}
	return exitError(ExitDependency, "%v", err)
}

func contextFailure(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return exitError(ExitCanceled, "scan timed out")
	}
	return exitError(ExitCanceled, "scan canceled")
}
