package archive

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUnicodePathExtraField(t *testing.T) {
	rawName := []byte{0xc4, 0xe3, 0xba, 0xc3, '.', 't', 'x', 't'}
	unicodeName := "你好.txt"
	field := make([]byte, 9+len(unicodeName))
	binary.LittleEndian.PutUint16(field[:2], 0x7075)
	binary.LittleEndian.PutUint16(field[2:4], uint16(5+len(unicodeName)))
	field[4] = 1
	binary.LittleEndian.PutUint32(field[5:9], crc32.ChecksumIEEE(rawName))
	copy(field[9:], unicodeName)
	file := &zip.File{FileHeader: zip.FileHeader{Name: string(rawName), NonUTF8: true, Extra: field}}

	name, nonUTF8, err := zipEntryName(file)
	if err != nil || nonUTF8 || name != unicodeName {
		t.Fatalf("zipEntryName() = %q, %v, %v", name, nonUTF8, err)
	}
	file.Extra[5] ^= 0xff
	if _, _, err := zipEntryName(file); err == nil {
		t.Fatal("zipEntryName accepted a stale Unicode path checksum")
	}
}

type zipEntry struct {
	name   string
	data   string
	mode   os.FileMode
	method uint16
}

func TestExtract(t *testing.T) {
	old := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	archivePath := makeZIP(t, []zipEntry{
		{name: "z.txt", data: "z", mode: 0o777},
		{name: "src/a.txt", data: "alpha", mode: 0o755},
	}, old)
	dest := filepath.Join(t.TempDir(), "out")

	files, stats, err := Extract(context.Background(), archivePath, dest, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"src/a.txt", "z.txt"}; !reflect.DeepEqual(files, want) {
		t.Fatalf("files = %q, want %q", files, want)
	}
	if stats.Entries != 2 || stats.Files != 2 || stats.Directories != 1 || stats.DeclaredBytes != 6 || stats.ExtractedBytes != 6 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	assertMode(t, dest, 0o700)
	assertMode(t, filepath.Join(dest, "src"), 0o700)
	assertMode(t, filepath.Join(dest, "src", "a.txt"), 0o600)
	content, err := os.ReadFile(filepath.Join(dest, "src", "a.txt"))
	if err != nil || string(content) != "alpha" {
		t.Fatalf("content = %q, err = %v", content, err)
	}
	info, err := os.Stat(filepath.Join(dest, "src", "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if info.ModTime().Equal(old) {
		t.Fatal("archive timestamp was preserved")
	}
}

func TestExtractNormalizesOutputPathToNFC(t *testing.T) {
	raw, normalized := "e\u0301.txt", "\u00e9.txt"
	archivePath := makeZIP(t, []zipEntry{{name: raw, data: "ok"}}, time.Time{})
	dest := filepath.Join(t.TempDir(), "out")

	files, stats, err := Extract(context.Background(), archivePath, dest, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{normalized}; !reflect.DeepEqual(files, want) {
		t.Fatalf("files = %q, want %q", files, want)
	}
	if stats.SourcePaths[normalized] != raw {
		t.Fatalf("source mapping = %q, want %q", stats.SourcePaths[normalized], raw)
	}
	if data, err := os.ReadFile(filepath.Join(dest, normalized)); err != nil || string(data) != "ok" {
		t.Fatalf("normalized output = %q, err = %v", data, err)
	}
	if _, err := os.Lstat(filepath.Join(dest, raw)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("raw non-NFC output exists: %v", err)
	}
}

func TestRejectsUnsafePathsBeforeCreatingDestination(t *testing.T) {
	for _, name := range []string{
		"../escape",
		"/absolute",
		"C:/windows",
		"a\\b",
		"a/./b",
		"a//b",
		"a/\x00b",
		"a/\nb",
	} {
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			archivePath := makeZIP(t, []zipEntry{{name: name, data: "x"}}, time.Time{})
			dest := filepath.Join(t.TempDir(), "out")
			_, _, err := Extract(context.Background(), archivePath, dest, DefaultLimits())
			if ErrorCode(err) != CodeUnsafePath {
				t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
			}
			if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("destination created during preflight: %v", statErr)
			}
		})
	}
}

func TestRejectsPathCollisions(t *testing.T) {
	for name, entries := range map[string][]zipEntry{
		"duplicate":         {{name: "a", data: "1"}, {name: "a", data: "2"}},
		"case fold":         {{name: "A.txt", data: "1"}, {name: "a.txt", data: "2"}},
		"NFC":               {{name: "\u00e9.txt", data: "1"}, {name: "e\u0301.txt", data: "2"}},
		"implicit dir case": {{name: "A/one", data: "1"}, {name: "a/two", data: "2"}},
		"file versus dir":   {{name: "a", data: "1"}, {name: "a/b", data: "2"}},
	} {
		t.Run(name, func(t *testing.T) {
			archivePath := makeZIP(t, entries, time.Time{})
			dest := filepath.Join(t.TempDir(), "out")
			_, _, err := Extract(context.Background(), archivePath, dest, DefaultLimits())
			if ErrorCode(err) != CodeDuplicatePath {
				t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
			}
			if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("destination created during preflight: %v", statErr)
			}
		})
	}
}

func TestOmitsUnsupportedEntryTypes(t *testing.T) {
	for name, test := range map[string]struct {
		mode os.FileMode
		code Code
	}{
		"symlink":    {mode: os.ModeSymlink | 0o777, code: CodeSymlink},
		"FIFO":       {mode: os.ModeNamedPipe | 0o600, code: CodeSpecialFile},
		"FIFO slash": {mode: os.ModeNamedPipe | 0o600, code: CodeSpecialFile},
	} {
		t.Run(name, func(t *testing.T) {
			entryName := "entry"
			data := "target"
			if name == "FIFO slash" {
				entryName += "/"
				data = ""
			}
			archivePath := makeZIP(t, []zipEntry{{name: entryName, data: data, mode: test.mode}, {name: "safe.txt", data: "safe"}}, time.Time{})
			dest := filepath.Join(t.TempDir(), "out")
			files, stats, err := Extract(context.Background(), archivePath, dest, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(files, []string{"safe.txt"}) || len(stats.Rejected) != 1 || stats.Rejected[0].Code != test.code {
				t.Fatalf("files=%v rejected=%+v", files, stats.Rejected)
			}
			if _, statErr := os.Lstat(filepath.Join(dest, "entry")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("special entry was restored: %v", statErr)
			}
		})
	}
}

func TestRejectsEncryptedEntry(t *testing.T) {
	archivePath := makeZIP(t, []zipEntry{{name: "a", data: "payload"}}, time.Time{})
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	central := bytes.Index(data, []byte{'P', 'K', 1, 2})
	if central < 0 {
		t.Fatal("central directory not found")
	}
	flags := binary.LittleEndian.Uint16(data[central+8 : central+10])
	binary.LittleEndian.PutUint16(data[central+8:central+10], flags|1)
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "out")
	_, _, err = Extract(context.Background(), archivePath, dest, DefaultLimits())
	if ErrorCode(err) != CodeEncrypted {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
	if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination created during preflight: %v", statErr)
	}
}

func TestRejectsMalformedAndUnsupportedZIP(t *testing.T) {
	t.Run("damaged central directory", func(t *testing.T) {
		archivePath := makeZIP(t, []zipEntry{{name: "a", data: "payload"}}, time.Time{})
		data, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(archivePath, data[:len(data)-5], 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Preflight(context.Background(), archivePath, DefaultLimits()); ErrorCode(err) != CodeInvalid {
			t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
		}
	})
	t.Run("unsupported compression", func(t *testing.T) {
		archivePath := makeZIP(t, []zipEntry{{name: "a", data: "payload"}}, time.Time{})
		data, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		central := bytes.Index(data, []byte{'P', 'K', 1, 2})
		local := bytes.Index(data, []byte{'P', 'K', 3, 4})
		if central < 0 || local < 0 {
			t.Fatal("ZIP headers not found")
		}
		binary.LittleEndian.PutUint16(data[central+10:central+12], 99)
		binary.LittleEndian.PutUint16(data[local+8:local+10], 99)
		if err := os.WriteFile(archivePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Preflight(context.Background(), archivePath, DefaultLimits()); ErrorCode(err) != CodeUnsupported {
			t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
		}
	})
}

func TestPreflightLimits(t *testing.T) {
	for name, test := range map[string]struct {
		entries []zipEntry
		change  func(*Limits)
	}{
		"entries": {
			entries: []zipEntry{{name: "a", data: "1"}, {name: "b", data: "2"}},
			change:  func(l *Limits) { l.MaxEntries = 1 },
		},
		"declared file": {
			entries: []zipEntry{{name: "a", data: "1234"}},
			change:  func(l *Limits) { l.MaxFileBytes = 3 },
		},
		"declared total": {
			entries: []zipEntry{{name: "a", data: "12"}, {name: "b", data: "34"}},
			change:  func(l *Limits) { l.MaxDeclaredBytes = 3 },
		},
		"compression ratio": {
			entries: []zipEntry{{name: "a", data: strings.Repeat("x", 1024), method: zip.Deflate}},
			change:  func(l *Limits) { l.MaxCompressionRatio = 2 },
		},
		"path depth": {
			entries: []zipEntry{{name: "a/b", data: "1"}},
			change:  func(l *Limits) { l.MaxPathDepth = 1 },
		},
		"path bytes": {
			entries: []zipEntry{{name: "abcd", data: "1"}},
			change:  func(l *Limits) { l.MaxPathBytes = 3 },
		},
		"component bytes": {
			entries: []zipEntry{{name: strings.Repeat("a", 256), data: "1"}},
			change:  func(*Limits) {},
		},
	} {
		t.Run(name, func(t *testing.T) {
			archivePath := makeZIP(t, test.entries, time.Time{})
			dest := filepath.Join(t.TempDir(), "out")
			limits := DefaultLimits()
			test.change(&limits)
			_, _, err := Extract(context.Background(), archivePath, dest, limits)
			if ErrorCode(err) != CodeLimitExceeded {
				t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
			}
			if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("destination created during preflight: %v", statErr)
			}
		})
	}
}

func TestEntryCountIsBoundedBeforeZIPReader(t *testing.T) {
	entries := make([]zipEntry, 11)
	for i := range entries {
		entries[i] = zipEntry{name: string(rune('a' + i)), data: "1"}
	}
	archivePath := makeZIP(t, entries, time.Time{})
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	eocd := bytes.LastIndex(data, []byte{'P', 'K', 5, 6})
	if eocd < 0 {
		t.Fatal("end of central directory not found")
	}
	binary.LittleEndian.PutUint16(data[eocd+8:eocd+10], 1)
	binary.LittleEndian.PutUint16(data[eocd+10:eocd+12], 1)
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxEntries = 10
	if _, err := Preflight(context.Background(), archivePath, limits); ErrorCode(err) != CodeLimitExceeded {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
}

func TestDeclaredEntryCountIsBoundedBeforeZIPReader(t *testing.T) {
	archivePath := makeZIP(t, []zipEntry{{name: "a", data: "1"}}, time.Time{})
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	eocd := bytes.LastIndex(data, []byte{'P', 'K', 5, 6})
	if eocd < 0 {
		t.Fatal("end of central directory not found")
	}
	binary.LittleEndian.PutUint16(data[eocd+8:eocd+10], 11)
	binary.LittleEndian.PutUint16(data[eocd+10:eocd+12], 11)
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxEntries = 10
	if _, err := Preflight(context.Background(), archivePath, limits); ErrorCode(err) != CodeLimitExceeded {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
}

func TestActualLimitAndCancellation(t *testing.T) {
	var output bytes.Buffer
	if _, err := copyAtMost(context.Background(), &output, strings.NewReader("1234"), 3); ErrorCode(err) != CodeLimitExceeded {
		t.Fatalf("limit code = %q, err = %v", ErrorCode(err), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := copyAtMost(ctx, &output, strings.NewReader("x"), 3); ErrorCode(err) != CodeCanceled || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel code = %q, err = %v", ErrorCode(err), err)
	}
}

func TestExtractEnforcesObservedByteLimit(t *testing.T) {
	archivePath := makeZIP(t, []zipEntry{{name: "a", data: "1234", method: zip.Deflate}}, time.Time{})
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	central := bytes.Index(data, []byte{'P', 'K', 1, 2})
	if central < 0 {
		t.Fatal("central directory not found")
	}
	binary.LittleEndian.PutUint32(data[central+24:central+28], 3)
	descriptor := bytes.Index(data, []byte{'P', 'K', 7, 8})
	if descriptor < 0 {
		t.Fatal("data descriptor not found")
	}
	binary.LittleEndian.PutUint32(data[descriptor+12:descriptor+16], 3)
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	limits := DefaultLimits()
	limits.MaxFileBytes, limits.MaxTotalBytes, limits.MaxDeclaredBytes = 3, 3, 3
	dest := filepath.Join(t.TempDir(), "out")
	if _, _, err := Extract(context.Background(), archivePath, dest, limits); ErrorCode(err) != CodeLimitExceeded {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
	if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination was not removed: %v", err)
	}
}

func TestChecksumFailureCleansDestination(t *testing.T) {
	archivePath := makeZIP(t, []zipEntry{{name: "a", data: "payload"}}, time.Time{})
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	central := bytes.Index(data, []byte{'P', 'K', 1, 2})
	if central < 0 {
		t.Fatal("central directory not found")
	}
	binary.LittleEndian.PutUint32(data[central+16:central+20], 0xdeadbeef)
	if err := os.WriteFile(archivePath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "out")
	_, stats, err := Extract(context.Background(), archivePath, dest, DefaultLimits())
	if ErrorCode(err) != CodeChecksum {
		t.Fatalf("code = %q, err = %v", ErrorCode(err), err)
	}
	if stats.ExtractedBytes != int64(len("payload")) {
		t.Fatalf("failed extraction accounted %d bytes", stats.ExtractedBytes)
	}
	if _, statErr := os.Lstat(dest); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial destination was not removed: %v", statErr)
	}
}

func makeZIP(t *testing.T, entries []zipEntry, modified time.Time) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "input.zip")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for _, item := range entries {
		header := &zip.FileHeader{Name: item.name, Method: item.method}
		if item.mode != 0 {
			header.SetMode(item.mode)
		}
		if !modified.IsZero() {
			header.SetModTime(modified)
		}
		entryWriter, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if item.data != "" {
			if _, err := entryWriter.Write([]byte(item.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

func FuzzSafeName(f *testing.F) {
	for _, seed := range []string{"file.txt", "../escape", "/absolute", "a\\b", "e\u0301.txt", "a/./b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, name string) {
		got, err := safeName(name, false, false, DefaultLimits())
		if err == nil && (got == "" || path.Clean(got) != got || strings.ContainsRune(got, '\\')) {
			t.Fatalf("unsafe accepted path %q", got)
		}
	})
}

// Keep encoding failures distinct from path traversal without guessing legacy encodings.
func TestZIPFilenameEncodingMatrix(t *testing.T) {
	uid := []byte{0x75, 0x78, 3, 0, 1, 0, 0}
	for _, tc := range []struct {
		name    string
		nonUTF8 bool
		extra   []byte
		want    string
	}{
		{"analysis.py", false, nil, ""},
		{"数据/分析.py", false, nil, ""},
		{"数据/分析.py", false, uid, ""},
		{"数据/分析.py", true, uid, "path is not UTF-8"},
		{"../分析.py", false, nil, "unsafe path component"},
		{"/分析.py", false, nil, "path is not relative POSIX syntax"},
		{"C:/分析.py", false, nil, "path is not relative POSIX syntax"},
		{"a\\分析.py", false, nil, "path is not relative POSIX syntax"},
		{"a\n分析.py", false, nil, "path contains a control character"},
	} {
		t.Run(tc.name+tc.want, func(t *testing.T) {
			var data bytes.Buffer
			writer := zip.NewWriter(&data)
			header := &zip.FileHeader{Name: tc.name, NonUTF8: tc.nonUTF8, Extra: tc.extra, Method: zip.Deflate}
			header.SetMode(0600)
			member, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = member.Write([]byte("print(1)")); err != nil {
				t.Fatal(err)
			}
			if err = writer.Close(); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(t.TempDir(), "sample.zip")
			if err = os.WriteFile(filename, data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			_, err = Preflight(context.Background(), filename, DefaultLimits())
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var failure *Error
			if !errors.As(err, &failure) || failure.Entry != tc.name || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected diagnostic: %v", err)
			}
		})
	}
}

func TestCompressedDirectories(t *testing.T) {
	var payload bytes.Buffer
	compressor, err := flate.NewWriter(&payload, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compressor.Write([]byte("hidden payload")); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		method uint16
		data   []byte
		size   uint64
		crc    uint32
		limit  int64
		want   Code
	}{
		{name: "stored empty", method: zip.Store},
		{name: "deflated empty", method: zip.Deflate, data: []byte{3, 0}},
		{name: "stored payload", method: zip.Store, data: []byte("x"), want: CodeInvalid},
		{name: "declared payload", method: zip.Deflate, data: payload.Bytes(), size: 14, want: CodeInvalid},
		{name: "hidden payload", method: zip.Deflate, data: payload.Bytes(), want: CodeInvalid},
		{name: "trailing payload", method: zip.Deflate, data: []byte{3, 0, 42}, want: CodeInvalid},
		{name: "corrupt stream", method: zip.Deflate, data: []byte{7}, want: CodeInvalid},
		{name: "truncated stream", method: zip.Deflate, data: []byte{3}, want: CodeInvalid},
		{name: "nonzero crc", method: zip.Deflate, data: []byte{3, 0}, crc: 1, want: CodeInvalid},
		{name: "compressed size limit", method: zip.Deflate, data: []byte{3, 0}, limit: 1, want: CodeLimitExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buffer bytes.Buffer
			writer := zip.NewWriter(&buffer)
			// Go's ZIP writer suppresses directory bodies; rename the placeholder
			// after writing to reproduce archives produced by Python and Java
			header := &zip.FileHeader{Name: "_rels!", Method: tc.method,
				CompressedSize64: uint64(len(tc.data)), UncompressedSize64: tc.size, CRC32: tc.crc}
			header.SetMode(os.ModeDir | 0o755)
			body, err := writer.CreateRaw(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := body.Write(tc.data); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			filename := filepath.Join(t.TempDir(), "input.zip")
			if err := os.WriteFile(filename, bytes.ReplaceAll(buffer.Bytes(), []byte("_rels!"), []byte("_rels/")), 0o600); err != nil {
				t.Fatal(err)
			}
			limits := DefaultLimits()
			if tc.limit != 0 {
				limits.MaxFileBytes = tc.limit
			}
			stats, err := Preflight(context.Background(), filename, limits)
			if ErrorCode(err) != tc.want {
				t.Fatalf("Preflight: stats=%+v err=%v, want %s", stats, err, tc.want)
			}
			dest := filepath.Join(t.TempDir(), "out")
			_, _, err = Extract(context.Background(), filename, dest, limits)
			if ErrorCode(err) != tc.want {
				t.Fatalf("Extract: err=%v, want %s", err, tc.want)
			}
			if tc.want != "" {
				if _, err := os.Lstat(dest); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("rejected archive created output: %v", err)
				}
			} else {
				if stats.Entries != 1 || stats.Directories != 1 || stats.Files != 0 {
					t.Fatalf("unexpected stats: %+v", stats)
				}
				assertMode(t, filepath.Join(dest, "_rels"), 0o700)
			}
		})
	}
}
