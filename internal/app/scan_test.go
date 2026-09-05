package app

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Xarth-Mai/Attachment-Gate/internal/batch"
	"github.com/Xarth-Mai/Attachment-Gate/internal/config"
	"github.com/Xarth-Mai/Attachment-Gate/internal/manifest"
)

func TestScanPublishesPartialManifest(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file/libmagic is not installed")
	}
	root := t.TempDir()
	quarantine := filepath.Join(root, "quarantine")
	results := filepath.Join(root, "results")
	batchID := "batch-01"
	batchDir := filepath.Join(quarantine, batchID)
	blobs := filepath.Join(batchDir, "blobs")
	for _, directory := range []string{blobs, results} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	nested := testZIP(t, map[string][]byte{"inside.txt": []byte("nested")})
	badDocument := corruptZIPCRC(t, testZIP(t, map[string][]byte{
		"[Content_Types].xml": []byte(`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`),
		"word/document.xml":   []byte(`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>`),
	}), "word/document.xml")
	project := testZIPWithSymlink(t, map[string][]byte{
		"bad.docx":     badDocument,
		"bin/tool.exe": testPE(),
		"e\u0301.txt":  []byte("accent\n"),
		"main.py":      []byte("print('ok')\n"),
		"inner.zip":    nested,
	}, "link", "main.py")
	files := []testUpload{
		{ID: "a1", Blob: "blob-a", Name: "notes.md", Data: []byte("# Notes\n")},
		{ID: "a2", Blob: "blob-b", Name: "project.zip", Data: project},
		{ID: "a3", Blob: "blob-c", Name: "paper.pdf", Data: testPE()},
	}
	writeTestBatch(t, batchDir, batchID, files)
	socketURL := startFakeClamd(t, []byte("not-present-in-fixtures"))
	configPath := filepath.Join(root, "config.yaml")
	configData := []byte("schema_version: 1\nroots:\n  quarantine: " + quarantine + "\n  results: " + results + "\nlimits:\n  max_discovered_files: 9\nmalware:\n  socket: " + socketURL + "\n")
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	resultDir := filepath.Join(results, batchID)
	t.Cleanup(func() { makeDirectoriesWritable(resultDir) })
	if err := Scan(context.Background(), ScanOptions{Input: batchDir, Output: resultDir, ConfigPath: configPath}); err != nil {
		t.Fatal(err)
	}

	manifestData, err := os.ReadFile(filepath.Join(resultDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(manifestData, []byte(root)) {
		t.Fatal("manifest exposes a server path")
	}
	var got manifest.Manifest
	if err := json.Unmarshal(manifestData, &got); err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "partial" || got.Summary.UploadedFiles != 3 || got.Summary.DiscoveredFiles != 9 || got.Summary.ApprovedFiles != 5 || got.Summary.RejectedFiles != 4 {
		t.Fatalf("unexpected result: outcome=%s summary=%+v", got.Outcome, got.Summary)
	}
	reasons := map[string]bool{}
	for _, file := range got.Files {
		if file.Reason != nil {
			reasons[file.Reason.Code] = true
		}
	}
	if !reasons["archive_checksum_error"] || !reasons["executable_not_allowed"] || !reasons["symlink_not_allowed"] {
		t.Fatalf("missing rejections: %v", reasons)
	}
	foundNestedWarning := false
	for _, file := range got.Files {
		for _, warning := range file.Warnings {
			if warning.Code == "nested_archive_not_allowed" {
				foundNestedWarning = true
			}
		}
	}
	if !foundNestedWarning {
		t.Fatal("nested archive did not warn and continue")
	}
	for _, relative := range []string{"01-notes.md", "02-project/main.py", "02-project/é.txt"} {
		info, err := os.Stat(filepath.Join(resultDir, "approved", relative))
		if err != nil || info.Mode().Perm() != 0o440 {
			t.Fatalf("approved file %s: mode=%v err=%v", relative, info, err)
		}
	}
	if _, err := os.Stat(filepath.Join(resultDir, "approved", "02-project.zip")); !os.IsNotExist(err) {
		t.Fatal("raw ZIP was published")
	}
	foundNormalizedMapping := false
	for _, file := range got.Files {
		if file.SourcePath == "project.zip!e\u0301.txt" && file.OutputPath != nil && *file.OutputPath == "02-project/é.txt" {
			foundNormalizedMapping = true
		}
	}
	if !foundNormalizedMapping {
		t.Fatal("manifest lost the original-to-normalized path mapping")
	}
	assertManifestMatchesOutput(t, resultDir, &got)
}

func TestScanRejectsMalwareInFileAndRawZIP(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file/libmagic is not installed")
	}
	root := t.TempDir()
	quarantine := filepath.Join(root, "quarantine")
	results := filepath.Join(root, "results")
	batchID := "batch-malware"
	batchDir := filepath.Join(quarantine, batchID)
	for _, directory := range []string{filepath.Join(batchDir, "blobs"), results} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	signature := []byte("X5O!P%@AP[4" + "\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	files := []testUpload{
		{ID: "clean", Blob: "blob-clean", Name: "clean.txt", Data: []byte("clean\n")},
		{ID: "bad", Blob: "blob-bad", Name: "bad.txt", Data: signature},
		{ID: "zip", Blob: "blob-zip", Name: "bad.zip", Data: testZIP(t, map[string][]byte{"bad.txt": signature, "good.txt": []byte("good")})},
	}
	writeTestBatch(t, batchDir, batchID, files)
	socketURL := startFakeClamd(t, signature)
	configPath := filepath.Join(root, "config.yaml")
	configData := []byte("schema_version: 1\nroots:\n  quarantine: " + quarantine + "\n  results: " + results + "\nmalware:\n  enabled: true\n  required: true\n  socket: " + socketURL + "\n")
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	resultDir := filepath.Join(results, batchID)
	t.Cleanup(func() { makeDirectoriesWritable(resultDir) })
	if err := Scan(context.Background(), ScanOptions{Input: batchDir, Output: resultDir, ConfigPath: configPath}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(resultDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got manifest.Manifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "partial" || got.Summary.ApprovedFiles != 1 || got.Summary.RejectedFiles != 2 || len(got.Files) != 3 {
		t.Fatalf("unexpected result: outcome=%s summary=%+v files=%d", got.Outcome, got.Summary, len(got.Files))
	}
	for _, file := range got.Files[1:] {
		if file.Reason == nil || file.Reason.Code != "malware_found" || file.OutputPath != nil {
			t.Fatalf("malware was not omitted: %+v", file)
		}
	}
}

func TestScanAllowsExecutableCodeZIPWithWarnings(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file/libmagic is not installed")
	}
	root := t.TempDir()
	quarantine, results, batchID := filepath.Join(root, "quarantine"), filepath.Join(root, "results"), "batch-code"
	batchDir := filepath.Join(quarantine, batchID)
	for _, directory := range []string{filepath.Join(batchDir, "blobs"), results} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	code := testZIP(t, map[string][]byte{
		"bin/server":     testPE(),
		"dist/index.html": []byte("<html>ok</html>"),
		"main.py":        []byte("print('ok')\n"),
	})
	writeTestBatch(t, batchDir, batchID, []testUpload{{ID: "code", Blob: "blob-code", Name: "code.zip", Data: code}})
	socketURL := startFakeClamd(t, nil)
	configPath := filepath.Join(root, "config.yaml")
	configData := []byte("schema_version: 1\nroots:\n  quarantine: " + quarantine + "\n  results: " + results + "\nmalware:\n  socket: " + socketURL + "\n")
	configData = append(configData, []byte("policy:\n  executable: warn\npaths:\n  exclude_directory_names: [.git, node_modules]\n")...)
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	resultDir := filepath.Join(results, batchID)
	t.Cleanup(func() { makeDirectoriesWritable(resultDir) })
	if err := Scan(context.Background(), ScanOptions{Input: batchDir, Output: resultDir, ConfigPath: configPath}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(resultDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got manifest.Manifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "all_approved" || got.Summary.RejectedFiles != 0 || got.Summary.ApprovedFiles != 4 {
		t.Fatalf("code ZIP was not fully approved: %+v", got.Summary)
	}
	for _, file := range got.Files {
		if file.Decision != "approved" {
			t.Fatalf("unexpected rejection: %+v", file)
		}
	}
	foundExecutableWarning := false
	for _, file := range got.Files {
		for _, warning := range file.Warnings {
			if warning.Code == "executable_found" {
				foundExecutableWarning = true
			}
		}
	}
	if !foundExecutableWarning {
		t.Fatal("executable member did not warn")
	}
	for _, relative := range []string{"01-code/bin/server", "01-code/dist/index.html"} {
		if _, err := os.Stat(filepath.Join(resultDir, "approved", relative)); err != nil {
			t.Fatalf("approved file %s missing: %v", relative, err)
		}
	}
}

func TestScanRejectsMalwarePerExtractedEntry(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file/libmagic is not installed")
	}
	root := t.TempDir()
	quarantine, results, batchID := filepath.Join(root, "quarantine"), filepath.Join(root, "results"), "batch-entry-malware"
	batchDir := filepath.Join(quarantine, batchID)
	for _, directory := range []string{filepath.Join(batchDir, "blobs"), results} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	signature := []byte("X5O!P%@AP[4" + "\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	archiveData := testZIP(t, map[string][]byte{"bad.txt": bytes.Repeat(signature, 8), "good.txt": []byte("good\n")})
	if bytes.Contains(archiveData, signature) {
		t.Fatal("test signature was not compressed")
	}
	writeTestBatch(t, batchDir, batchID, []testUpload{{ID: "zip", Blob: "blob-zip", Name: "files.zip", Data: archiveData}})
	socketURL := startFakeClamd(t, signature, false)
	configPath := filepath.Join(root, "config.yaml")
	configData := []byte("schema_version: 1\nroots:\n  quarantine: " + quarantine + "\n  results: " + results + "\nmalware:\n  socket: " + socketURL + "\n")
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	resultDir := filepath.Join(results, batchID)
	t.Cleanup(func() { makeDirectoriesWritable(resultDir) })
	if err := Scan(context.Background(), ScanOptions{Input: batchDir, Output: resultDir, ConfigPath: configPath}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(resultDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got manifest.Manifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "partial" || got.Summary.ApprovedFiles != 2 || got.Summary.RejectedFiles != 1 || len(got.Files) != 3 {
		t.Fatalf("unexpected result: outcome=%s summary=%+v files=%d", got.Outcome, got.Summary, len(got.Files))
	}
	if got.Files[1].Reason == nil || got.Files[1].Reason.Code != "malware_found" {
		t.Fatalf("infected entry was not rejected: %+v", got.Files[1])
	}
	if _, err := os.Stat(filepath.Join(resultDir, "approved", "01-files", "good.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(resultDir, "approved", "01-files", "bad.txt")); !os.IsNotExist(err) {
		t.Fatal("infected archive entry was published")
	}
}

func TestSnapshotInputPinsValidatedBytes(t *testing.T) {
	staging := t.TempDir()
	source := filepath.Join(t.TempDir(), "blob")
	original := []byte("validated")
	if err := os.WriteFile(source, original, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(original)
	file := &batch.File{Path: source, Size: int64(len(original)), SHA256: hex.EncodeToString(digest[:])}
	snapshot, err := snapshotInput(context.Background(), staging, file, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(snapshot); err != nil || !bytes.Equal(got, original) {
		t.Fatalf("snapshot = %q, err = %v", got, err)
	}
}

func TestDetectorTimeoutPolicy(t *testing.T) {
	cfg := config.Default()
	cfg.Policy.DetectorError = "reject_batch"
	s := scanner{cfg: &cfg}
	record := manifest.File{Warnings: []manifest.Warning{}}
	err := s.detectorFailure(context.Background(), &record, context.DeadlineExceeded)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitCanceled {
		t.Fatalf("batch timeout error = %v", err)
	}
	cfg.Policy.DetectorError = "reject_file"
	s = scanner{cfg: &cfg}
	if err := s.detectorFailure(context.Background(), &record, context.DeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	if len(s.files) != 1 || s.files[0].Reason == nil || s.files[0].Reason.Code != "type_detector_error" {
		t.Fatalf("file timeout was not recorded: %+v", s.files)
	}
}

func TestCheckDirectoryRejectsOtherWritableRoot(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o707); err != nil {
		t.Fatal(err)
	}
	if err := checkDirectory(directory, false); err == nil {
		t.Fatal("other-writable root was accepted")
	}
}

func TestCheckDirectoryRejectsGroupWritableResults(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := checkDirectory(directory, true); err == nil {
		t.Fatal("group-writable results root was accepted")
	}
}

func TestDoctorFailsClosedWithoutClamd(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file/libmagic is not installed")
	}
	root := t.TempDir()
	quarantine := filepath.Join(root, "quarantine")
	results := filepath.Join(root, "results")
	for _, directory := range []string{quarantine, results} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(root, "config.yaml")
	data := []byte("schema_version: 1\nroots:\n  quarantine: " + quarantine + "\n  results: " + results + "\nmalware:\n  socket: unix://" + filepath.Join(root, "missing.sock") + "\n")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Doctor(context.Background(), configPath)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitDependency {
		t.Fatalf("doctor did not fail closed: %v", err)
	}
}

func TestScanRejectsClamdStreamLimitAsFile(t *testing.T) {
	socketURL := startFakeClamdServer(t, &fakeClamd{scanError: "INSTREAM size limit exceeded"})
	resultDir, err := runOneFileScan(t, socketURL, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(resultDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got manifest.Manifest
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Outcome != "none_approved" || len(got.Files) != 1 || got.Files[0].Reason == nil || got.Files[0].Reason.Code != "malware_scan_error" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestScanClamdTimeoutDoesNotPublish(t *testing.T) {
	socketURL := startFakeClamdServer(t, &fakeClamd{needle: []byte("not-present"), inspectArchives: true, scanDelay: 200 * time.Millisecond})
	resultDir, err := runOneFileScan(t, socketURL, "limits:\n  file_scan_timeout: 100ms\n")
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitCanceled {
		t.Fatalf("timeout error = %v", err)
	}
	if _, err := os.Lstat(resultDir); !os.IsNotExist(err) {
		t.Fatalf("timed-out scan published output: %v", err)
	}
}

func TestDoctorRejectsStaleMalwareDatabase(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file/libmagic is not installed")
	}
	root := t.TempDir()
	quarantine, results := filepath.Join(root, "quarantine"), filepath.Join(root, "results")
	for _, directory := range []string{quarantine, results} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	socketURL := startFakeClamdServer(t, &fakeClamd{databaseTime: time.Now().Add(-73 * time.Hour)})
	configPath := filepath.Join(root, "config.yaml")
	data := []byte("schema_version: 1\nroots:\n  quarantine: " + quarantine + "\n  results: " + results + "\nmalware:\n  socket: " + socketURL + "\n")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	err := Doctor(context.Background(), configPath)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitDependency {
		t.Fatalf("stale database error = %v", err)
	}
}

func runOneFileScan(t *testing.T, socketURL, extraConfig string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file/libmagic is not installed")
	}
	root := t.TempDir()
	quarantine, results, batchID := filepath.Join(root, "quarantine"), filepath.Join(root, "results"), "batch-one"
	batchDir := filepath.Join(quarantine, batchID)
	for _, directory := range []string{filepath.Join(batchDir, "blobs"), results} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeTestBatch(t, batchDir, batchID, []testUpload{{ID: "one", Blob: "blob", Name: "note.txt", Data: []byte("hello\n")}})
	configPath := filepath.Join(root, "config.yaml")
	configData := []byte("schema_version: 1\nroots:\n  quarantine: " + quarantine + "\n  results: " + results + "\n" + extraConfig + "malware:\n  socket: " + socketURL + "\n")
	if err := os.WriteFile(configPath, configData, 0o600); err != nil {
		t.Fatal(err)
	}
	resultDir := filepath.Join(results, batchID)
	t.Cleanup(func() { makeDirectoriesWritable(resultDir) })
	return resultDir, Scan(context.Background(), ScanOptions{Input: batchDir, Output: resultDir, ConfigPath: configPath})
}

type testUpload struct {
	ID, Blob, Name string
	Data           []byte
}

func writeTestBatch(t *testing.T, directory, batchID string, files []testUpload) {
	t.Helper()
	type uploadFile struct {
		AttachmentID        string `json:"attachment_id"`
		BlobName            string `json:"blob_name"`
		OriginalName        string `json:"original_name"`
		DeclaredContentType string `json:"declared_content_type"`
		UploadedSize        int64  `json:"uploaded_size"`
		UploadedSHA256      string `json:"uploaded_sha256"`
	}
	upload := struct {
		SchemaVersion int          `json:"schema_version"`
		BatchID       string       `json:"batch_id"`
		Files         []uploadFile `json:"files"`
	}{SchemaVersion: 1, BatchID: batchID}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(directory, "blobs", file.Blob), file.Data, 0o600); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(file.Data)
		upload.Files = append(upload.Files, uploadFile{
			AttachmentID: file.ID, BlobName: file.Blob, OriginalName: file.Name,
			DeclaredContentType: "application/octet-stream", UploadedSize: int64(len(file.Data)),
			UploadedSHA256: hex.EncodeToString(digest[:]),
		})
	}
	data, err := json.Marshal(upload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "upload.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testZIP(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	for name, body := range entries {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func testZIPWithSymlink(t *testing.T, entries map[string][]byte, name, target string) []byte {
	t.Helper()
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	for entryName, body := range entries {
		entry, err := w.Create(entryName)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	header := &zip.FileHeader{Name: name, Method: zip.Store}
	header.SetMode(os.ModeSymlink | 0o777)
	entry, err := w.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(target)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func corruptZIPCRC(t *testing.T, data []byte, entryName string) []byte {
	t.Helper()
	data = append([]byte(nil), data...)
	eocd := bytes.LastIndex(data, []byte{'P', 'K', 5, 6})
	if eocd < 0 {
		t.Fatal("end of central directory not found")
	}
	for offset := int(binary.LittleEndian.Uint32(data[eocd+16 : eocd+20])); offset+46 <= eocd; {
		if !bytes.Equal(data[offset:offset+4], []byte{'P', 'K', 1, 2}) {
			break
		}
		nameSize := int(binary.LittleEndian.Uint16(data[offset+28 : offset+30]))
		extraSize := int(binary.LittleEndian.Uint16(data[offset+30 : offset+32]))
		commentSize := int(binary.LittleEndian.Uint16(data[offset+32 : offset+34]))
		if offset+46+nameSize+extraSize+commentSize > eocd {
			t.Fatal("invalid central directory")
		}
		if string(data[offset+46:offset+46+nameSize]) == entryName {
			binary.LittleEndian.PutUint32(data[offset+16:offset+20], binary.LittleEndian.Uint32(data[offset+16:offset+20])^0xffffffff)
			return data
		}
		offset += 46 + nameSize + extraSize + commentSize
	}
	t.Fatalf("ZIP entry %q not found", entryName)
	return nil
}

func assertManifestMatchesOutput(t *testing.T, resultDir string, got *manifest.Manifest) {
	t.Helper()
	for name, mode := range map[string]os.FileMode{"": 0o550, "approved": 0o550, "manifest.json": 0o440} {
		info, err := os.Stat(filepath.Join(resultDir, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%q mode=%v err=%v", name, info, err)
		}
	}
	if got.Engines.Malware == nil || len(got.Policy.SHA256) != sha256.Size*2 {
		t.Fatalf("missing engine or policy identity: %+v %+v", got.Engines, got.Policy)
	}
	expectedFiles := map[string]bool{}
	for _, record := range got.Files {
		if record.Decision != "approved" {
			if record.OutputPath != nil {
				t.Fatalf("rejected record has output: %+v", record)
			}
			continue
		}
		if record.OutputPath == nil {
			t.Fatalf("approved record has no output: %+v", record)
		}
		outputPath := filepath.Join(resultDir, "approved", filepath.FromSlash(*record.OutputPath))
		info, err := os.Stat(outputPath)
		if err != nil {
			t.Fatal(err)
		}
		if record.Kind == "container" {
			if !info.IsDir() {
				t.Fatalf("container output is not a directory: %s", outputPath)
			}
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o440 {
			t.Fatalf("approved output mode: %s %v", outputPath, info.Mode())
		}
		digest, size, err := hashFile(context.Background(), outputPath)
		if err != nil || digest != record.SHA256 || size != record.Size {
			t.Fatalf("approved output mismatch: %s digest=%s size=%d err=%v", outputPath, digest, size, err)
		}
		expectedFiles[*record.OutputPath] = true
	}
	approvedRoot := filepath.Join(resultDir, "approved")
	if err := filepath.WalkDir(approvedRoot, func(filePath string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(approvedRoot, filePath)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !expectedFiles[relative] {
			return errors.New("undeclared approved file: " + relative)
		}
		delete(expectedFiles, relative)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(expectedFiles) != 0 {
		t.Fatalf("manifest outputs are missing: %v", expectedFiles)
	}
}

func testPE() []byte {
	data := make([]byte, 1024)
	copy(data, "MZ")
	binary.LittleEndian.PutUint16(data[2:], 0x90)
	binary.LittleEndian.PutUint16(data[4:], 3)
	binary.LittleEndian.PutUint16(data[8:], 4)
	binary.LittleEndian.PutUint16(data[0x18:], 0x40)
	binary.LittleEndian.PutUint32(data[0x3c:], 0x80)
	copy(data[0x40:], "This program cannot be run in DOS mode.\r\n$")
	copy(data[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[0x84:], 0x14c)
	binary.LittleEndian.PutUint16(data[0x86:], 1)
	binary.LittleEndian.PutUint16(data[0x94:], 0xe0)
	binary.LittleEndian.PutUint16(data[0x96:], 0x0102)
	binary.LittleEndian.PutUint16(data[0x98:], 0x10b)
	binary.LittleEndian.PutUint32(data[0xa8:], 0x1000)
	binary.LittleEndian.PutUint32(data[0xb4:], 0x400000)
	binary.LittleEndian.PutUint32(data[0xb8:], 0x1000)
	binary.LittleEndian.PutUint32(data[0xbc:], 0x200)
	binary.LittleEndian.PutUint32(data[0xd0:], 0x2000)
	binary.LittleEndian.PutUint32(data[0xd4:], 0x200)
	binary.LittleEndian.PutUint16(data[0xdc:], 3)
	binary.LittleEndian.PutUint32(data[0xf4:], 16)
	copy(data[0x178:], ".text")
	binary.LittleEndian.PutUint32(data[0x180:], 1)
	binary.LittleEndian.PutUint32(data[0x184:], 0x1000)
	binary.LittleEndian.PutUint32(data[0x188:], 0x200)
	binary.LittleEndian.PutUint32(data[0x18c:], 0x200)
	binary.LittleEndian.PutUint32(data[0x19c:], 0x60000020)
	return data
}

func makeDirectoriesWritable(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
}

type fakeClamd struct {
	listener        net.Listener
	wait            sync.WaitGroup
	needle          []byte
	inspectArchives bool
	databaseTime    time.Time
	scanDelay       time.Duration
	scanError       string
}

func startFakeClamd(t *testing.T, needle []byte, inspectArchives ...bool) string {
	t.Helper()
	inspect := true
	if len(inspectArchives) != 0 {
		inspect = inspectArchives[0]
	}
	return startFakeClamdServer(t, &fakeClamd{needle: needle, inspectArchives: inspect, databaseTime: time.Now()})
}

func startFakeClamdServer(t *testing.T, server *fakeClamd) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "clamd.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("Unix sockets are unavailable: %v", err)
	}
	server.listener = listener
	if server.databaseTime.IsZero() {
		server.databaseTime = time.Now()
	}
	server.wait.Add(1)
	go func() {
		defer server.wait.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			server.handle(connection)
			_ = connection.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		server.wait.Wait()
	})
	return "unix://" + socket
}

func (s *fakeClamd) handle(connection net.Conn) {
	reader := bufio.NewReader(connection)
	command, err := reader.ReadString(0)
	if err != nil {
		return
	}
	switch command {
	case "zPING\x00":
		_, _ = connection.Write([]byte("PONG\x00"))
	case "zVERSION\x00":
		version := "ClamAV 1.0.0/1/" + s.databaseTime.Format("Mon Jan _2 15:04:05 2006") + "\x00"
		_, _ = connection.Write([]byte(version))
	case "zINSTREAM\x00":
		var body bytes.Buffer
		for {
			var size [4]byte
			if _, err := io.ReadFull(reader, size[:]); err != nil {
				return
			}
			n := binary.BigEndian.Uint32(size[:])
			if n == 0 {
				break
			}
			if _, err := io.CopyN(&body, reader, int64(n)); err != nil {
				return
			}
		}
		if s.scanDelay != 0 {
			time.Sleep(s.scanDelay)
		}
		response := "stream: OK\x00"
		if s.scanError != "" {
			response = "stream: " + s.scanError + " ERROR\x00"
		} else if containsMalware(body.Bytes(), s.needle, s.inspectArchives) {
			response = "stream: Test-Signature FOUND\x00"
		}
		_, _ = connection.Write([]byte(response))
	}
}

func containsMalware(data, needle []byte, inspectArchives bool) bool {
	if len(needle) != 0 && bytes.Contains(data, needle) {
		return true
	}
	if !inspectArchives {
		return false
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false
	}
	for _, entry := range reader.File {
		file, err := entry.Open()
		if err != nil {
			continue
		}
		body, readErr := io.ReadAll(file)
		closeErr := file.Close()
		if len(needle) != 0 && readErr == nil && closeErr == nil && bytes.Contains(body, needle) {
			return true
		}
	}
	return false
}
