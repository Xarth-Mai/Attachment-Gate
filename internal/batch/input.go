package batch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Xarth-Mai/Attachment-Gate/internal/config"
)

const (
	uploadFileName       = "upload.json"
	blobsDirectory       = "blobs"
	maxUploadBytes       = 16 << 20
	maxBatchIDBytes      = 128
	maxAttachmentIDBytes = 128
	maxBlobNameBytes     = 255
	maxOriginalNameBytes = 1 << 10
	maxContentTypeBytes  = 255
)

type Input struct {
	SchemaVersion int    `json:"schema_version"`
	BatchID       string `json:"batch_id"`
	Files         []File `json:"files"`
}

type File struct {
	AttachmentID        string `json:"attachment_id"`
	BlobName            string `json:"blob_name"`
	OriginalName        string `json:"original_name"`
	DeclaredContentType string `json:"declared_content_type"`
	UploadedSize        int64  `json:"uploaded_size"`
	UploadedSHA256      string `json:"uploaded_sha256"`

	Path   string `json:"-"`
	Size   int64  `json:"-"`
	SHA256 string `json:"-"`
}

// Load treats dir as untrusted. It returns only after upload.json and the
// frozen blobs directory agree byte-for-byte.
func Load(dir string, cfg *config.Config) (*Input, error) {
	return LoadContext(context.Background(), dir, cfg)
}

// LoadContext is Load with cancellation for potentially long reads.
func LoadContext(ctx context.Context, dir string, cfg *config.Config) (*Input, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || filepath.Dir(dir) != cfg.Roots.Quarantine {
		return nil, fmt.Errorf("batch directory must be a clean direct child of the quarantine root")
	}
	quarantine, err := openDirectory(cfg.Roots.Quarantine)
	if err != nil {
		return nil, fmt.Errorf("quarantine root: %w", err)
	}
	quarantineInfo, statErr := quarantine.Stat()
	if statErr != nil || quarantineInfo.Mode().Perm()&0o002 != 0 {
		_ = quarantine.Close()
		return nil, fmt.Errorf("quarantine root is not trusted")
	}
	if err := quarantine.Close(); err != nil {
		return nil, fmt.Errorf("close quarantine root: %w", err)
	}

	rootEntries, batchInfo, err := readDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("batch directory: %w", err)
	}
	if err := validateRootEntries(rootEntries); err != nil {
		return nil, err
	}

	uploadPath := filepath.Join(dir, uploadFileName)
	uploadFile, uploadInfo, err := openRegular(uploadPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", uploadFileName, err)
	}
	data, err := readBounded(ctx, uploadFile, uploadInfo.Size(), maxUploadBytes)
	closeErr := uploadFile.Close()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", uploadFileName, err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close %s: %w", uploadFileName, closeErr)
	}

	input, err := decode(data)
	if err != nil {
		return nil, err
	}
	if err := validateDeclarations(input, filepath.Base(dir), cfg.Limits); err != nil {
		return nil, err
	}

	declared := make(map[string]struct{}, len(input.Files))
	for i := range input.Files {
		declared[input.Files[i].BlobName] = struct{}{}
	}
	blobsPath := filepath.Join(dir, blobsDirectory)
	blobEntries, blobsInfo, err := readDirectory(blobsPath)
	if err != nil {
		return nil, fmt.Errorf("blobs directory: %w", err)
	}
	if err := validateBlobEntries(blobEntries, declared); err != nil {
		return nil, err
	}

	total := int64(0)
	snapshots := make(map[string]os.FileInfo, len(input.Files))
	for i := range input.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file := &input.Files[i]
		path := filepath.Join(blobsPath, file.BlobName)
		size, digest, info, err := hashRegular(ctx, path, file.UploadedSize)
		if err != nil {
			return nil, fmt.Errorf("blob %q: %w", file.BlobName, err)
		}
		if !strings.EqualFold(digest, file.UploadedSHA256) {
			return nil, fmt.Errorf("blob %q SHA-256 does not match upload.json", file.BlobName)
		}
		if size > int64(cfg.Limits.MaxInputTotalSize)-total {
			return nil, fmt.Errorf("actual input size exceeds max_input_total_size")
		}
		total += size
		file.Path, file.Size, file.SHA256 = path, size, digest
		snapshots[file.BlobName] = info
	}

	if err := unchanged(dir, batchInfo); err != nil {
		return nil, fmt.Errorf("batch directory changed during validation: %w", err)
	}
	if err := unchanged(uploadPath, uploadInfo); err != nil {
		return nil, fmt.Errorf("%s changed during validation: %w", uploadFileName, err)
	}
	finalRootEntries, finalBatchInfo, err := readDirectory(dir)
	if err != nil {
		return nil, fmt.Errorf("recheck batch directory: %w", err)
	}
	if !sameSnapshot(batchInfo, finalBatchInfo) {
		return nil, fmt.Errorf("batch directory changed during validation")
	}
	if err := validateRootEntries(finalRootEntries); err != nil {
		return nil, err
	}
	finalEntries, finalBlobsInfo, err := readDirectory(blobsPath)
	if err != nil {
		return nil, fmt.Errorf("recheck blobs directory: %w", err)
	}
	if !sameSnapshot(blobsInfo, finalBlobsInfo) {
		return nil, fmt.Errorf("blobs directory changed during validation")
	}
	if err := validateBlobEntries(finalEntries, declared); err != nil {
		return nil, err
	}
	for name, info := range snapshots {
		if err := unchanged(filepath.Join(blobsPath, name), info); err != nil {
			return nil, fmt.Errorf("blob %q changed during validation: %w", name, err)
		}
	}
	return input, nil
}

func decode(data []byte) (*Input, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("%s is not valid UTF-8", uploadFileName)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var input Input
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("decode %s: %w", uploadFileName, err)
	}
	if input.Files == nil {
		return nil, fmt.Errorf("decode %s: files must be an array", uploadFileName)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode %s: trailing JSON value", uploadFileName)
		}
		return nil, fmt.Errorf("decode %s: %w", uploadFileName, err)
	}
	return &input, nil
}

func validateDeclarations(input *Input, directoryID string, limits config.Limits) error {
	if input.SchemaVersion != config.SchemaVersion {
		return fmt.Errorf("upload schema_version must be %d", config.SchemaVersion)
	}
	if !validID(input.BatchID, maxBatchIDBytes) || input.BatchID != directoryID {
		return fmt.Errorf("batch_id must match the batch directory name")
	}
	if len(input.Files) > limits.MaxInputFiles {
		return fmt.Errorf("file count exceeds max_input_files")
	}

	attachmentIDs := make(map[string]struct{}, len(input.Files))
	blobNames := make(map[string]struct{}, len(input.Files))
	total := int64(0)
	for i := range input.Files {
		file := &input.Files[i]
		if !validID(file.AttachmentID, maxAttachmentIDBytes) {
			return fmt.Errorf("files[%d].attachment_id is invalid", i)
		}
		if _, duplicate := attachmentIDs[file.AttachmentID]; duplicate {
			return fmt.Errorf("duplicate attachment_id %q", file.AttachmentID)
		}
		attachmentIDs[file.AttachmentID] = struct{}{}

		if !validBaseName(file.BlobName) || len(file.BlobName) > min(maxBlobNameBytes, limits.MaxRelativePathBytes) {
			return fmt.Errorf("files[%d].blob_name must be a plain basename", i)
		}
		if _, duplicate := blobNames[file.BlobName]; duplicate {
			return fmt.Errorf("duplicate blob_name %q", file.BlobName)
		}
		blobNames[file.BlobName] = struct{}{}

		if !validBaseName(file.OriginalName) || len(file.OriginalName) > maxOriginalNameBytes {
			return fmt.Errorf("files[%d].original_name is invalid", i)
		}
		if len(file.DeclaredContentType) > maxContentTypeBytes || hasControl(file.DeclaredContentType) {
			return fmt.Errorf("files[%d].declared_content_type is invalid", i)
		}
		if file.UploadedSize < 0 {
			return fmt.Errorf("files[%d].uploaded_size must not be negative", i)
		}
		if file.UploadedSize > int64(limits.MaxInputTotalSize)-total {
			return fmt.Errorf("declared input size exceeds max_input_total_size")
		}
		total += file.UploadedSize
		if len(file.UploadedSHA256) != sha256.Size*2 {
			return fmt.Errorf("files[%d].uploaded_sha256 must be a SHA-256 digest", i)
		}
		if _, err := hex.DecodeString(file.UploadedSHA256); err != nil {
			return fmt.Errorf("files[%d].uploaded_sha256 must be hexadecimal", i)
		}
	}
	return nil
}

func validateRootEntries(entries []os.DirEntry) error {
	if len(entries) != 2 {
		return fmt.Errorf("batch directory must contain only %s and %s", uploadFileName, blobsDirectory)
	}
	foundUpload, foundBlobs := false, false
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect batch entry %q: %w", entry.Name(), err)
		}
		switch entry.Name() {
		case uploadFileName:
			foundUpload = info.Mode().IsRegular()
		case blobsDirectory:
			foundBlobs = info.IsDir() && info.Mode()&os.ModeSymlink == 0
		default:
			return fmt.Errorf("undeclared batch entry %q", entry.Name())
		}
	}
	if !foundUpload || !foundBlobs {
		return fmt.Errorf("batch entries must be a regular %s and a real %s directory", uploadFileName, blobsDirectory)
	}
	return nil
}

func validateBlobEntries(entries []os.DirEntry, declared map[string]struct{}) error {
	if len(entries) != len(declared) {
		return fmt.Errorf("blobs directory does not exactly match upload.json")
	}
	for _, entry := range entries {
		if _, ok := declared[entry.Name()]; !ok {
			return fmt.Errorf("undeclared blob %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect blob %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("blob %q is a symlink or special file", entry.Name())
		}
	}
	return nil
}

func hashRegular(ctx context.Context, path string, declaredSize int64) (int64, string, os.FileInfo, error) {
	file, info, err := openRegular(path)
	if err != nil {
		return 0, "", nil, err
	}
	defer file.Close()
	if info.Size() != declaredSize {
		return 0, "", nil, fmt.Errorf("size does not match upload.json")
	}

	hash := sha256.New()
	reader := io.Reader(file)
	if declaredSize < int64(^uint64(0)>>1) {
		reader = io.LimitReader(file, declaredSize+1)
	}
	size, err := io.Copy(hash, contextReader{ctx: ctx, reader: reader})
	if err != nil {
		return 0, "", nil, fmt.Errorf("hash: %w", err)
	}
	if size != declaredSize {
		return 0, "", nil, fmt.Errorf("size changed while hashing")
	}
	after, err := file.Stat()
	if err != nil {
		return 0, "", nil, fmt.Errorf("stat after hashing: %w", err)
	}
	if !os.SameFile(info, after) || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return 0, "", nil, fmt.Errorf("file changed while hashing")
	}
	return size, hex.EncodeToString(hash.Sum(nil)), after, nil
}

func openRegular(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	after, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		file.Close()
		return nil, nil, fmt.Errorf("file changed while opening")
	}
	return file, after, nil
}

func openDirectory(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("not a real directory")
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := directory.Stat()
	if err != nil {
		directory.Close()
		return nil, err
	}
	if !after.IsDir() || !os.SameFile(before, after) {
		directory.Close()
		return nil, fmt.Errorf("directory changed while opening")
	}
	return directory, nil
}

func readDirectory(path string) ([]os.DirEntry, os.FileInfo, error) {
	directory, err := openDirectory(path)
	if err != nil {
		return nil, nil, err
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return nil, nil, err
	}
	entries, err := directory.ReadDir(-1)
	return entries, info, err
}

func readBounded(ctx context.Context, file *os.File, size, maximum int64) ([]byte, error) {
	if size < 0 || size > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	data, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: file}, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size {
		return nil, fmt.Errorf("file changed while reading")
	}
	return data, nil
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

func unchanged(path string, before os.FileInfo) error {
	after, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !sameSnapshot(before, after) {
		return fmt.Errorf("filesystem entry was replaced or modified")
	}
	return nil
}

func sameSnapshot(before, after os.FileInfo) bool {
	return os.SameFile(before, after) && after.Mode() == before.Mode() && after.Size() == before.Size() &&
		after.ModTime().Equal(before.ModTime())
}

func validBaseName(value string) bool {
	return value != "" && value != "." && value != ".." && filepath.Base(value) == value &&
		!strings.ContainsAny(value, `/\`) && !hasControl(value)
}

func validID(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, `/\`) && !hasControl(value)
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
