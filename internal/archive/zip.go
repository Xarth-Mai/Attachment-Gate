// Package archive extracts ZIP files without trusting archive metadata or paths.
package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const maxPathComponentBytes = 255

const maxEOCDSize = 65 << 10

// Code is a stable machine-readable extraction failure reason.
type Code string

const (
	CodeInvalid       Code = "archive_invalid"
	CodeEncrypted     Code = "archive_encrypted"
	CodeLimitExceeded Code = "archive_limit_exceeded"
	CodeUnsafePath    Code = "archive_path_unsafe"
	CodeDuplicatePath Code = "archive_duplicate_path"
	CodeChecksum      Code = "archive_checksum_error"
	CodeUnsupported   Code = "archive_unsupported"
	CodeSymlink       Code = "symlink_not_allowed"
	CodeSpecialFile   Code = "special_file_not_allowed"
	CodeCanceled      Code = "archive_canceled"
	CodeIO            Code = "archive_io_error"
	CodeInvalidLimits Code = "archive_limits_invalid"
)

// Error is an extraction error. Entry is an archive-relative name, never a
// host path.
type Error struct {
	Code  Code
	Entry string
	Err   error
}

func (e *Error) Error() string {
	if e.Entry != "" {
		return fmt.Sprintf("%s: entry %q: %v", e.Code, e.Entry, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// ErrorCode returns a stable code, or the empty string for non-archive errors.
func ErrorCode(err error) Code {
	var archiveErr *Error
	if errors.As(err, &archiveErr) {
		return archiveErr.Code
	}
	return ""
}

// Limits bounds both archive metadata and bytes observed while extracting.
// Every field must be positive.
type Limits struct {
	MaxEntries          int
	MaxDeclaredBytes    int64
	MaxFileBytes        int64
	MaxTotalBytes       int64
	MaxCompressionRatio uint64
	MaxPathDepth        int
	MaxPathBytes        int
}

// DefaultLimits returns the conservative v1 limits.
func DefaultLimits() Limits {
	return Limits{
		MaxEntries:          2000,
		MaxDeclaredBytes:    300 << 20,
		MaxFileBytes:        50 << 20,
		MaxTotalBytes:       300 << 20,
		MaxCompressionRatio: 200,
		MaxPathDepth:        20,
		MaxPathBytes:        512,
	}
}

// Preflight validates ZIP metadata and paths without reading file bodies.
func Preflight(ctx context.Context, zipPath string, limits Limits) (Stats, error) {
	if err := validateLimits(limits); err != nil {
		return Stats{}, err
	}
	if err := contextError(ctx); err != nil {
		return Stats{}, err
	}
	zr, err := openReader(zipPath, limits.MaxEntries)
	if err != nil {
		return Stats{}, err
	}
	defer zr.Close()
	entries, nodes, declared, err := preflight(ctx, zr.File, limits)
	if err != nil {
		return Stats{}, err
	}
	files, directories := 0, 0
	var rejected []RejectedEntry
	for _, item := range entries {
		if !item.isDir {
			files++
		}
		if item.reject != "" {
			rejected = append(rejected, RejectedEntry{SourcePath: item.source, Path: item.name, Code: item.reject, Size: int64(item.file.UncompressedSize64)})
		}
	}
	for _, item := range nodes {
		if item.isDir {
			directories++
		}
	}
	return Stats{Entries: len(entries), Files: files, Directories: directories, DeclaredBytes: declared, Rejected: rejected}, nil
}

// RejectedEntry is a safe-to-report archive member omitted by policy.
type RejectedEntry struct {
	SourcePath string
	Path       string
	Code       Code
	Size       int64
	SHA256     string
}

// Stats describes work performed while inspecting or extracting a container.
type Stats struct {
	Entries        int
	Files          int
	Directories    int
	DeclaredBytes  int64
	ExtractedBytes int64
	Rejected       []RejectedEntry
	SourcePaths    map[string]string
}

type entry struct {
	file   *zip.File
	source string
	name   string
	isDir  bool
	reject Code
}

type node struct {
	isDir    bool
	explicit bool
}

// Extract validates zipPath, creates freshDest with mode 0700, and extracts
// regular files with mode 0600. Returned paths are sorted, slash-separated,
// and relative to freshDest. Any failure after destination creation removes
// the destination and all partial output.
func Extract(ctx context.Context, zipPath, freshDest string, limits Limits) (_ []string, stats Stats, err error) {
	if err := validateLimits(limits); err != nil {
		return nil, Stats{}, err
	}
	if err := contextError(ctx); err != nil {
		return nil, Stats{}, err
	}

	zr, openErr := openReader(zipPath, limits.MaxEntries)
	if openErr != nil {
		return nil, Stats{}, openErr
	}
	defer zr.Close()

	entries, nodes, declared, err := preflight(ctx, zr.File, limits)
	if err != nil {
		return nil, Stats{}, err
	}
	stats.Entries = len(entries)
	stats.DeclaredBytes = declared
	stats.SourcePaths = make(map[string]string, len(entries))
	if statErr := destinationAbsent(freshDest); statErr != nil {
		return nil, stats, statErr
	}
	if mkdirErr := os.Mkdir(freshDest, 0o700); mkdirErr != nil {
		return nil, stats, coded(CodeIO, "", mkdirErr)
	}
	created := true
	defer func() {
		if err == nil || !created {
			return
		}
		if cleanupErr := os.RemoveAll(freshDest); cleanupErr != nil {
			err = errors.Join(err, coded(CodeIO, "", cleanupErr))
		}
	}()
	if chmodErr := os.Chmod(freshDest, 0o700); chmodErr != nil {
		return nil, stats, coded(CodeIO, "", chmodErr)
	}

	dirs := make([]string, 0, len(nodes))
	for name, n := range nodes {
		if n.isDir {
			dirs = append(dirs, name)
		}
	}
	// A path always sorts before its descendants, so lexical order is enough.
	sort.Strings(dirs)
	stats.Directories = len(dirs)
	for _, name := range dirs {
		if err := contextError(ctx); err != nil {
			return nil, stats, err
		}
		target := filepath.Join(freshDest, filepath.FromSlash(name))
		if mkdirErr := os.Mkdir(target, 0o700); mkdirErr != nil {
			return nil, stats, coded(CodeIO, name, mkdirErr)
		}
		if chmodErr := os.Chmod(target, 0o700); chmodErr != nil {
			return nil, stats, coded(CodeIO, name, chmodErr)
		}
	}

	files := make([]string, 0, len(entries))
	var extracted int64
	for _, item := range entries {
		if item.isDir {
			continue
		}
		if err := contextError(ctx); err != nil {
			return nil, stats, err
		}
		remaining := limits.MaxTotalBytes - extracted
		allowed := min(limits.MaxFileBytes, remaining)
		if item.reject != "" {
			rejected, n, consumeErr := consumeRejected(ctx, item, allowed)
			extracted += n
			stats.ExtractedBytes = extracted
			if consumeErr != nil {
				return nil, stats, consumeErr
			}
			stats.Rejected = append(stats.Rejected, rejected)
			continue
		}
		target := filepath.Join(freshDest, filepath.FromSlash(item.name))
		out, openErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			return nil, stats, coded(CodeIO, item.name, openErr)
		}
		if chmodErr := out.Chmod(0o600); chmodErr != nil {
			out.Close()
			return nil, stats, coded(CodeIO, item.name, chmodErr)
		}

		src, openErr := item.file.Open()
		if openErr != nil {
			out.Close()
			return nil, stats, classifyZIPError(item.source, openErr)
		}
		checksum := crc32.NewIEEE()
		n, copyErr := copyAtMost(ctx, io.MultiWriter(out, checksum), src, allowed)
		srcCloseErr := src.Close()
		outCloseErr := out.Close()
		if errors.Is(copyErr, zip.ErrFormat) && item.file.UncompressedSize64 >= uint64(allowed) && n < allowed {
			n = allowed
		}
		extracted += n
		stats.ExtractedBytes = extracted
		if copyErr != nil {
			if errors.Is(copyErr, zip.ErrFormat) && item.file.UncompressedSize64 >= uint64(allowed) {
				return nil, stats, coded(CodeLimitExceeded, item.source, errors.New("actual extracted size exceeds limit"))
			}
			return nil, stats, classifyZIPError(item.source, copyErr)
		}
		if srcCloseErr != nil {
			return nil, stats, classifyZIPError(item.source, srcCloseErr)
		}
		if outCloseErr != nil {
			return nil, stats, coded(CodeIO, item.name, outCloseErr)
		}
		if checksum.Sum32() != item.file.CRC32 {
			return nil, stats, coded(CodeChecksum, item.source, zip.ErrChecksum)
		}
		files = append(files, item.name)
		stats.SourcePaths[item.name] = item.source
	}

	sort.Strings(files)
	stats.Files = len(files)
	return files, stats, nil
}

func consumeRejected(ctx context.Context, item entry, allowed int64) (RejectedEntry, int64, error) {
	src, err := item.file.Open()
	if err != nil {
		return RejectedEntry{}, 0, classifyZIPError(item.source, err)
	}
	hash := sha256.New()
	checksum := crc32.NewIEEE()
	n, copyErr := copyAtMost(ctx, io.MultiWriter(io.Discard, hash, checksum), src, allowed)
	closeErr := src.Close()
	if errors.Is(copyErr, zip.ErrFormat) && item.file.UncompressedSize64 >= uint64(allowed) && n < allowed {
		n = allowed
	}
	if copyErr != nil {
		if errors.Is(copyErr, zip.ErrFormat) && item.file.UncompressedSize64 >= uint64(allowed) {
			return RejectedEntry{}, n, coded(CodeLimitExceeded, item.source, errors.New("actual extracted size exceeds limit"))
		}
		return RejectedEntry{}, n, classifyZIPError(item.source, copyErr)
	}
	if closeErr != nil {
		return RejectedEntry{}, n, classifyZIPError(item.source, closeErr)
	}
	if checksum.Sum32() != item.file.CRC32 {
		return RejectedEntry{}, n, coded(CodeChecksum, item.source, zip.ErrChecksum)
	}
	return RejectedEntry{SourcePath: item.source, Path: item.name, Code: item.reject, Size: n, SHA256: hex.EncodeToString(hash.Sum(nil))}, n, nil
}

// openReader bounds the central-directory entry count before archive/zip
// allocates one File per entry.
func openReader(zipPath string, maxEntries int) (*zip.ReadCloser, error) {
	if err := checkEntryCount(zipPath, maxEntries); err != nil {
		return nil, err
	}
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, coded(CodeInvalid, "", err)
	}
	return reader, nil
}

func checkEntryCount(zipPath string, maxEntries int) error {
	file, err := os.Open(zipPath)
	if err != nil {
		return coded(CodeInvalid, "", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return coded(CodeInvalid, "", err)
	}
	size := min(info.Size(), int64(maxEOCDSize))
	if size < 22 {
		return nil
	}
	tail := make([]byte, size)
	if _, err := file.ReadAt(tail, info.Size()-size); err != nil {
		return coded(CodeInvalid, "", err)
	}
	signature := []byte{'P', 'K', 5, 6}
	for offset := len(tail) - 22; offset >= 0; offset-- {
		if !bytes.Equal(tail[offset:offset+4], signature) {
			continue
		}
		commentSize := int(binary.LittleEndian.Uint16(tail[offset+20 : offset+22]))
		if offset+22+commentSize > len(tail) {
			continue
		}
		if binary.LittleEndian.Uint16(tail[offset+4:offset+6]) != 0 ||
			binary.LittleEndian.Uint16(tail[offset+6:offset+8]) != 0 {
			return coded(CodeUnsupported, "", errors.New("multi-disk ZIP is not supported"))
		}
		declaredEntries := binary.LittleEndian.Uint16(tail[offset+10 : offset+12])
		directorySize := binary.LittleEndian.Uint32(tail[offset+12 : offset+16])
		directoryOffset := binary.LittleEndian.Uint32(tail[offset+16 : offset+20])
		eocdOffset := info.Size() - size + int64(offset)
		if declaredEntries == math.MaxUint16 || directorySize == math.MaxUint32 || directoryOffset == math.MaxUint32 || hasZIP64Locator(file, eocdOffset) {
			return coded(CodeUnsupported, "", errors.New("ZIP64 is not supported"))
		}
		if int(declaredEntries) > maxEntries {
			return coded(CodeLimitExceeded, "", errors.New("too many entries"))
		}
		directoryStart := eocdOffset - int64(directorySize)
		baseOffset := directoryStart - int64(directoryOffset)
		if directoryStart < 0 {
			return coded(CodeInvalid, "", errors.New("invalid central directory offset"))
		}
		entries, err := countCentralHeaders(file, directoryStart, eocdOffset, maxEntries)
		if err != nil {
			return err
		}
		if entries > maxEntries {
			return coded(CodeLimitExceeded, "", errors.New("too many entries"))
		}
		// archive/zip may ignore a positive base offset when a central
		// directory also starts at the raw EOCD offset. Bound both paths.
		if baseOffset > 0 && int64(directoryOffset) != directoryStart {
			entries, err = countCentralHeaders(file, int64(directoryOffset), eocdOffset, maxEntries)
			if err != nil {
				return err
			}
			if entries > maxEntries {
				return coded(CodeLimitExceeded, "", errors.New("too many entries"))
			}
		}
		return nil
	}
	return nil
}

func hasZIP64Locator(file *os.File, eocdOffset int64) bool {
	if eocdOffset < 20 {
		return false
	}
	var signature [4]byte
	_, err := file.ReadAt(signature[:], eocdOffset-20)
	return err == nil && binary.LittleEndian.Uint32(signature[:]) == 0x07064b50
}

func countCentralHeaders(file *os.File, offset, end int64, maxEntries int) (int, error) {
	var header [46]byte
	for count := 0; ; count++ {
		if count > maxEntries {
			return count, nil
		}
		if offset+int64(len(header)) > end {
			return count, nil
		}
		if _, err := file.ReadAt(header[:], offset); err != nil {
			return 0, coded(CodeInvalid, "", err)
		}
		if binary.LittleEndian.Uint32(header[:4]) != 0x02014b50 {
			return count, nil
		}
		variable := int64(binary.LittleEndian.Uint16(header[28:30])) +
			int64(binary.LittleEndian.Uint16(header[30:32])) +
			int64(binary.LittleEndian.Uint16(header[32:34]))
		offset += int64(len(header)) + variable
		if offset > end {
			return 0, coded(CodeInvalid, "", errors.New("invalid central directory entry"))
		}
	}
}

func validateLimits(l Limits) error {
	if l.MaxEntries <= 0 || l.MaxDeclaredBytes <= 0 || l.MaxFileBytes <= 0 ||
		l.MaxTotalBytes <= 0 || l.MaxCompressionRatio == 0 || l.MaxPathDepth <= 0 ||
		l.MaxPathBytes <= 0 {
		return coded(CodeInvalidLimits, "", errors.New("every limit must be positive"))
	}
	return nil
}

func destinationAbsent(dest string) error {
	_, err := os.Lstat(dest)
	if err == nil {
		return coded(CodeIO, "", errors.New("destination already exists"))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return coded(CodeIO, "", err)
	}
	return nil
}

func preflight(ctx context.Context, files []*zip.File, limits Limits) ([]entry, map[string]node, int64, error) {
	if len(files) > limits.MaxEntries {
		return nil, nil, 0, coded(CodeLimitExceeded, "", errors.New("too many entries"))
	}
	entries := make([]entry, 0, len(files))
	nodes := make(map[string]node, len(files))
	nfcNames := make(map[string]string, len(files))
	foldedNames := make(map[string]string, len(files))
	folder := cases.Fold()
	var declared int64

	for _, file := range files {
		if err := contextError(ctx); err != nil {
			return nil, nil, 0, err
		}
		if file.Flags&(1<<0|1<<6|1<<13) != 0 {
			return nil, nil, 0, coded(CodeEncrypted, file.Name, errors.New("encrypted entry"))
		}
		if file.Method != zip.Store && file.Method != zip.Deflate {
			return nil, nil, 0, coded(CodeUnsupported, file.Name, errors.New("unsupported compression method"))
		}

		modeType := file.Mode().Type()
		var reject Code
		if modeType&os.ModeSymlink != 0 {
			reject = CodeSymlink
		} else if modeType != 0 && modeType != os.ModeDir {
			reject = CodeSpecialFile
		}
		isDir := modeType == os.ModeDir
		if isDir && (file.UncompressedSize64 != 0 || file.CompressedSize64 != 0 || file.CRC32 != 0) {
			return nil, nil, 0, coded(CodeInvalid, file.Name, errors.New("directory has data"))
		}

		entryName, nonUTF8, nameErr := zipEntryName(file)
		if nameErr != nil {
			return nil, nil, 0, coded(CodeUnsafePath, file.Name, nameErr)
		}
		rawName, pathErr := safeName(entryName, nonUTF8, isDir || reject != "" && strings.HasSuffix(entryName, "/"), limits)
		if pathErr != nil {
			return nil, nil, 0, pathErr
		}
		rawParts := strings.Split(rawName, "/")
		name := norm.NFC.String(rawName)
		if len(name) > limits.MaxPathBytes {
			return nil, nil, 0, coded(CodeLimitExceeded, rawName, errors.New("normalized path exceeds byte limit"))
		}
		for i := range rawParts {
			rawPrefix := strings.Join(rawParts[:i+1], "/")
			prefix := norm.NFC.String(rawPrefix)
			prefixDir := i < len(rawParts)-1 || isDir
			folded := norm.NFC.String(folder.String(prefix))
			if other, collision := nfcNames[prefix]; collision && other != rawPrefix {
				return nil, nil, 0, coded(CodeDuplicatePath, rawName, errors.New("NFC path collision"))
			}
			if other, collision := foldedNames[folded]; collision && other != rawPrefix {
				return nil, nil, 0, coded(CodeDuplicatePath, rawName, errors.New("case-folded path collision"))
			}
			existing, exists := nodes[prefix]
			if exists {
				if existing.isDir != prefixDir || i == len(rawParts)-1 && existing.explicit {
					return nil, nil, 0, coded(CodeDuplicatePath, rawName, errors.New("duplicate or conflicting path"))
				}
				if i == len(rawParts)-1 {
					existing.explicit = true
					nodes[prefix] = existing
				}
				continue
			}
			nodes[prefix] = node{isDir: prefixDir, explicit: i == len(rawParts)-1}
			nfcNames[prefix] = rawPrefix
			foldedNames[folded] = rawPrefix
		}

		if file.UncompressedSize64 > uint64(limits.MaxFileBytes) && !isDir {
			return nil, nil, 0, coded(CodeLimitExceeded, rawName, errors.New("declared file size exceeds limit"))
		}
		if file.UncompressedSize64 > uint64(limits.MaxDeclaredBytes)-uint64(declared) {
			return nil, nil, 0, coded(CodeLimitExceeded, rawName, errors.New("declared total size exceeds limit"))
		}
		declared += int64(file.UncompressedSize64)
		if file.UncompressedSize64 > 0 && ratioExceeds(file.UncompressedSize64, file.CompressedSize64, limits.MaxCompressionRatio) {
			return nil, nil, 0, coded(CodeLimitExceeded, rawName, errors.New("compression ratio exceeds limit"))
		}
		entries = append(entries, entry{file: file, source: rawName, name: name, isDir: isDir, reject: reject})
	}
	return entries, nodes, declared, nil
}

func zipEntryName(file *zip.File) (string, bool, error) {
	if !file.NonUTF8 {
		return file.Name, false, nil
	}
	rawName := []byte(file.Name)
	extra := file.Extra
	for len(extra) >= 4 {
		fieldID := binary.LittleEndian.Uint16(extra[:2])
		fieldSize := int(binary.LittleEndian.Uint16(extra[2:4]))
		extra = extra[4:]
		if fieldSize > len(extra) {
			return "", true, errors.New("invalid ZIP extra field")
		}
		field := extra[:fieldSize]
		extra = extra[fieldSize:]
		if fieldID != 0x7075 {
			continue
		}
		if len(field) < 5 || field[0] != 1 {
			return "", true, errors.New("invalid Unicode path extra field")
		}
		if binary.LittleEndian.Uint32(field[1:5]) != crc32.ChecksumIEEE(rawName) {
			return "", true, errors.New("Unicode path checksum mismatch")
		}
		name := field[5:]
		if len(name) == 0 || !utf8.Valid(name) {
			return "", true, errors.New("Unicode path is not UTF-8")
		}
		return string(name), false, nil
	}
	if len(extra) != 0 {
		return "", true, errors.New("invalid ZIP extra field")
	}
	return file.Name, true, nil
}

func safeName(name string, nonUTF8, isDir bool, limits Limits) (string, error) {
	if nonUTF8 || !utf8.ValidString(name) {
		return "", coded(CodeUnsafePath, name, errors.New("path is not UTF-8"))
	}
	if name == "" || strings.ContainsRune(name, '\\') || strings.HasPrefix(name, "/") || hasWindowsDrive(name) {
		return "", coded(CodeUnsafePath, name, errors.New("path is not relative POSIX syntax"))
	}
	for _, r := range name {
		if r == 0 || unicode.IsControl(r) {
			return "", coded(CodeUnsafePath, name, errors.New("path contains a control character"))
		}
	}

	cleanName := name
	if isDir && strings.HasSuffix(cleanName, "/") {
		cleanName = strings.TrimSuffix(cleanName, "/")
	}
	if cleanName == "" || path.Clean(cleanName) != cleanName {
		return "", coded(CodeUnsafePath, name, errors.New("path changes when cleaned"))
	}
	parts := strings.Split(cleanName, "/")
	if len(parts) > limits.MaxPathDepth || len(cleanName) > limits.MaxPathBytes {
		return "", coded(CodeLimitExceeded, name, errors.New("path limit exceeded"))
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", coded(CodeUnsafePath, name, errors.New("unsafe path component"))
		}
		if len(norm.NFC.String(part)) > maxPathComponentBytes {
			return "", coded(CodeLimitExceeded, name, errors.New("path component exceeds filesystem limit"))
		}
	}
	return cleanName, nil
}

func hasWindowsDrive(name string) bool {
	return len(name) >= 2 && name[1] == ':' && (name[0] >= 'A' && name[0] <= 'Z' || name[0] >= 'a' && name[0] <= 'z')
}

func ratioExceeds(uncompressed, compressed, maxRatio uint64) bool {
	if compressed == 0 {
		return true
	}
	quotient, remainder := uncompressed/compressed, uncompressed%compressed
	return quotient > maxRatio || quotient == maxRatio && remainder != 0
}

func copyAtMost(ctx context.Context, dst io.Writer, src io.Reader, limit int64) (int64, error) {
	if limit < 0 || limit == math.MaxInt64 {
		return 0, coded(CodeLimitExceeded, "", errors.New("byte limit exhausted"))
	}
	limited := &io.LimitedReader{R: src, N: limit + 1}
	buffer := make([]byte, 32<<10)
	var written int64
	for {
		if err := contextError(ctx); err != nil {
			return written, err
		}
		n, readErr := limited.Read(buffer)
		if n > 0 {
			if written+int64(n) > limit {
				return limit, coded(CodeLimitExceeded, "", errors.New("actual extracted size exceeds limit"))
			}
			writeN, writeErr := dst.Write(buffer[:n])
			written += int64(writeN)
			if writeErr != nil {
				return written, coded(CodeIO, "", writeErr)
			}
			if writeN != n {
				return written, coded(CodeIO, "", io.ErrShortWrite)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return coded(CodeCanceled, "", err)
	}
	return nil
}

func classifyZIPError(entry string, err error) error {
	var archiveErr *Error
	if errors.As(err, &archiveErr) {
		if archiveErr.Entry == "" {
			archiveErr.Entry = entry
		}
		return archiveErr
	}
	if errors.Is(err, zip.ErrChecksum) {
		return coded(CodeChecksum, entry, err)
	}
	if errors.Is(err, zip.ErrAlgorithm) {
		return coded(CodeUnsupported, entry, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return coded(CodeCanceled, entry, err)
	}
	return coded(CodeInvalid, entry, err)
}

func coded(code Code, entry string, err error) error {
	return &Error{Code: code, Entry: entry, Err: err}
}
