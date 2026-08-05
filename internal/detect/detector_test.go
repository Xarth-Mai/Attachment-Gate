package detect

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInspectZIP(t *testing.T) {
	tests := []struct {
		name    string
		entries map[string]string
		want    Type
	}{
		{"plain zip", map[string]string{"notes.txt": "hello"}, TypeArchiveZIP},
		{"docx", map[string]string{"[Content_Types].xml": `<Types/>`, "word/document.xml": "<w/>"}, TypeDocumentDOCX},
		{"xlsx", map[string]string{"[Content_Types].xml": `<Types/>`, "xl/workbook.xml": "<x/>"}, TypeDocumentXLSX},
		{"pptx", map[string]string{"[Content_Types].xml": `<Types/>`, "ppt/presentation.xml": "<p/>"}, TypeDocumentPPTX},
		{"ambiguous office roots", map[string]string{"[Content_Types].xml": `<Types/>`, "word/a": "", "xl/a": ""}, TypeArchiveZIP},
		{"macro part", map[string]string{"[Content_Types].xml": `<Types/>`, "word/document.xml": "", "word/vbaProject.bin": "macro"}, TypeOfficeMacro},
		{"macro part in plain zip", map[string]string{"vbaProject.bin": "macro"}, TypeOfficeMacro},
		{"macro content type", map[string]string{"[Content_Types].xml": `<Override ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/>`, "word/document.xml": ""}, TypeOfficeMacro},
		{"jar", map[string]string{"META-INF/MANIFEST.MF": "Manifest-Version: 1.0"}, TypeApplicationPackage},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filePath := writeZIP(t, test.entries)
			got, err := inspectZIP(context.Background(), filePath)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("inspectZIP() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTextRequiresValidEncodingBeforeExtensionClassification(t *testing.T) {
	validPath := writeFile(t, "blob", []byte("print('hello')\n"))
	got, err := (Detector{}).classify(context.Background(), validPath, Result{MIME: "text/plain", Extension: ".py"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeTextSource {
		t.Fatalf("valid source = %q, want %q", got.Type, TypeTextSource)
	}

	invalidPath := writeFile(t, "blob", []byte{0xff, 0xfe, 0x00})
	got, err = (Detector{}).classify(context.Background(), invalidPath, Result{MIME: "application/octet-stream", Extension: ".py"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeUnknownBinary {
		t.Fatalf("invalid source = %q, want %q", got.Type, TypeUnknownBinary)
	}

	svgPath := writeFile(t, "drawing.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`))
	got, err = (Detector{}).classify(context.Background(), svgPath, Result{MIME: "image/svg+xml", Extension: ".svg"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeUnknownBinary {
		t.Fatalf("SVG = %q, want %q", got.Type, TypeUnknownBinary)
	}
	got, err = (Detector{}).classify(context.Background(), svgPath, Result{MIME: "text/plain", Extension: ".svg"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeUnknownBinary {
		t.Fatalf("text-like SVG = %q, want %q", got.Type, TypeUnknownBinary)
	}
}

func TestHtmlCssClassifiedAsTextSource(t *testing.T) {
	tests := []struct {
		ext, mime string
	}{
		{".html", "text/html"},
		{".htm", "text/html"},
		{".css", "text/css"},
	}
	for _, test := range tests {
		path := writeFile(t, "blob", []byte("<!doctype html><p>hi</p>"))
		got, err := (Detector{}).classify(context.Background(), path, Result{MIME: test.mime, Extension: test.ext})
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != TypeTextSource {
			t.Fatalf("%s = %q, want %q", test.ext, got.Type, TypeTextSource)
		}
	}
}

func TestTextEncodings(t *testing.T) {
	utf16LE := []byte{0xff, 0xfe, 'h', 0, 'i', 0}
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"UTF-8", []byte("hello, 世界\n"), true},
		{"UTF-16 LE BOM", utf16LE, true},
		{"invalid UTF-8", []byte{0xff}, false},
		{"odd UTF-16", []byte{0xff, 0xfe, 'x'}, false},
		{"too many NULs", bytes.Repeat([]byte{0}, 100), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := validTextFile(context.Background(), writeFile(t, "text", test.data))
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("validTextFile() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestClassificationHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	filePath := writeFile(t, "text", []byte("hello"))
	if _, err := validTextFile(ctx, filePath); !errors.Is(err, context.Canceled) {
		t.Fatalf("text error = %v", err)
	}
	if _, err := (Detector{}).classify(ctx, filePath, Result{MIME: "text/plain"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("classification error = %v", err)
	}
}

func TestImagePixelLimit(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "image.png")
	file, err := os.Create(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(file, image.NewRGBA(image.Rect(0, 0, 10, 10))); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = (Detector{MaxImagePixels: 99}).classify(context.Background(), filePath, Result{MIME: "image/png", Extension: ".png"})
	if !errors.Is(err, ErrImageDimensionsExceeded) {
		t.Fatalf("classify() error = %v, want ErrImageDimensionsExceeded", err)
	}
	if _, err := (Detector{MaxImagePixels: 100}).classify(context.Background(), filePath, Result{MIME: "image/png", Extension: ".png"}); err != nil {
		t.Fatal(err)
	}
}

func TestWebPDimensions(t *testing.T) {
	tests := []struct {
		chunk   string
		payload []byte
		width   int
		height  int
	}{
		{"VP8X", []byte{0, 0, 0, 0, 9, 0, 0, 19, 0, 0}, 10, 20},
		{"VP8L", []byte{0x2f, 1, 0x80, 0, 0}, 2, 3},
		{"VP8 ", []byte{0, 0, 0, 0x9d, 0x01, 0x2a, 12, 0, 13, 0}, 12, 13},
	}
	for _, test := range tests {
		t.Run(test.chunk, func(t *testing.T) {
			header := append([]byte("RIFF\x16\x00\x00\x00WEBP"+test.chunk),
				byte(len(test.payload)), 0, 0, 0)
			header = append(header, test.payload...)
			width, height, err := webPDimensions(context.Background(), bytes.NewReader(header))
			if err != nil {
				t.Fatal(err)
			}
			if width != test.width || height != test.height {
				t.Fatalf("webPDimensions() = %dx%d, want %dx%d", width, height, test.width, test.height)
			}
		})
	}
}

func TestDangerousMIMEMapping(t *testing.T) {
	tests := map[string]Type{
		"application/vnd.microsoft.portable-executable": TypeExecutablePE,
		"application/x-executable":                      TypeExecutableELF,
		"application/x-mach-binary":                     TypeExecutableMachO,
		"application/x-sharedlib":                       TypeSharedLibrary,
		"application/x-object":                          TypeObjectFile,
		"application/vnd.android.package-archive":       TypeApplicationPackage,
		"application/x-iso9660-image":                   TypeDiskImage,
		"application/x-ole-storage":                     TypeLegacyOffice,
		"application/octet-stream":                      TypeUnknownBinary,
	}
	for mediaType, want := range tests {
		if got := typeFromMIME(mediaType); got != want {
			t.Errorf("typeFromMIME(%q) = %q, want %q", mediaType, got, want)
		}
	}
}

func TestDetectAsUsesLogicalExtension(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file command is not installed")
	}
	physicalPath := writeFile(t, "opaque.bin", []byte("print('hello')\n"))
	got, err := (Detector{}).DetectAs(context.Background(), physicalPath, "main.py")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != TypeTextSource || got.Extension != ".py" {
		t.Fatalf("DetectAs() = %#v, want text_source with .py", got)
	}
}

func TestDetectAsUsesContentBeforeMisleadingExtension(t *testing.T) {
	if _, err := exec.LookPath("file"); err != nil {
		t.Skip("file command is not installed")
	}
	detector := Detector{}
	tests := []struct {
		physical string
		logical  string
		want     Type
	}{
		{writeFile(t, "pdf.bin", []byte("%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n")), "image.png", TypeDocumentPDF},
		{writeFile(t, "elf.bin", testELF()), "notes.txt", TypeExecutableELF},
		{writeZIP(t, map[string]string{"[Content_Types].xml": `<Types/>`, "word/document.xml": "<w/>"}), "document.zip", TypeDocumentDOCX},
		{writeZIP(t, map[string]string{"note.txt": "hello"}), "document.docx", TypeArchiveZIP},
		{writeFile(t, "text.bin", []byte("hello\n")), "README", TypeTextPlain},
	}
	for _, test := range tests {
		got, err := detector.DetectAs(context.Background(), test.physical, test.logical)
		if err != nil {
			t.Fatal(err)
		}
		if got.Type != test.want {
			t.Errorf("DetectAs(%q) = %q (%s), want %q", test.logical, got.Type, got.MIME, test.want)
		}
	}
}

func testELF() []byte {
	data := make([]byte, 64)
	copy(data, "\x7fELF")
	data[4], data[5], data[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(data[16:18], 2)
	binary.LittleEndian.PutUint16(data[18:20], 62)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	return data
}

func writeZIP(t *testing.T, entries map[string]string) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), "sample.zip")
	file, err := os.Create(filePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, body := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	filePath := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(filePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func FuzzTypeFromMIME(f *testing.F) {
	for _, seed := range []string{"application/pdf", "application/zip", "application/x-executable", "text/plain", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, mediaType string) {
		if got := typeFromMIME(mediaType); got == "" {
			t.Fatal("empty internal type")
		}
	})
}
