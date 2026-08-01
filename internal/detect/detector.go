package detect

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	securezip "github.com/Xarth-Mai/Attachment-Gate/internal/archive"
)

type Type string

const (
	TypeDocumentPDF        Type = "document_pdf"
	TypeDocumentDOCX       Type = "document_docx"
	TypeDocumentXLSX       Type = "document_xlsx"
	TypeDocumentPPTX       Type = "document_pptx"
	TypeTextPlain          Type = "text_plain"
	TypeTextSource         Type = "text_source"
	TypeTextData           Type = "text_data"
	TypeImagePNG           Type = "image_png"
	TypeImageJPEG          Type = "image_jpeg"
	TypeImageWebP          Type = "image_webp"
	TypeArchiveZIP         Type = "archive_zip"
	TypeLegacyOffice       Type = "legacy_office"
	TypeOfficeMacro        Type = "office_macro"
	TypeExecutablePE       Type = "executable_pe"
	TypeExecutableELF      Type = "executable_elf"
	TypeExecutableMachO    Type = "executable_macho"
	TypeSharedLibrary      Type = "shared_library"
	TypeObjectFile         Type = "object_file"
	TypeApplicationPackage Type = "application_package"
	TypeDiskImage          Type = "disk_image"
	TypeUnknownBinary      Type = "unknown_binary"
)

const (
	defaultMaxImagePixels = 40_000_000
	maxContentTypesSize   = 1 << 20
)

var (
	ErrInvalidImage            = errors.New("invalid image")
	ErrImageDimensionsExceeded = errors.New("image dimensions exceeded")
)

type Result struct {
	Type      Type   `json:"type"`
	MIME      string `json:"mime"`
	Extension string `json:"extension"`
}

type Detector struct {
	FileCommand    string
	MaxImagePixels uint64
	ArchiveLimits  securezip.Limits
}

func (d Detector) Detect(ctx context.Context, filePath string) (Result, error) {
	return d.DetectAs(ctx, filePath, filePath)
}

// DetectAs reads filePath and uses logicalName only for extension classification.
func (d Detector) DetectAs(ctx context.Context, filePath, logicalName string) (Result, error) {
	extension := strings.ToLower(filepath.Ext(logicalName))
	result := Result{Type: TypeUnknownBinary, Extension: extension}
	command := d.FileCommand
	if command == "" {
		command = "file"
	}

	out, err := exec.CommandContext(ctx, command, "--brief", "--mime-type", "--", filePath).Output()
	if err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		return result, fmt.Errorf("detect MIME: %w", err)
	}
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(string(out)))
	if err != nil {
		return result, fmt.Errorf("parse MIME: %w", err)
	}
	result.MIME = strings.ToLower(mediaType)
	return d.classify(ctx, filePath, result)
}

func (d Detector) Version(ctx context.Context) (string, error) {
	command := d.FileCommand
	if command == "" {
		command = "file"
	}
	out, err := exec.CommandContext(ctx, command, "--version").Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return "", fmt.Errorf("file version: %w", err)
	}
	version := strings.TrimSpace(string(out))
	if version == "" {
		return "", errors.New("empty file version")
	}
	return version, nil
}

func (d Detector) classify(ctx context.Context, filePath string, result Result) (Result, error) {
	if err := ctx.Err(); err != nil {
		return result, err
	}
	result.Type = typeFromMIME(result.MIME)
	if isZIPMIME(result.MIME) || result.Type == TypeOfficeMacro {
		declaredMacro := result.Type == TypeOfficeMacro
		result.Type = TypeArchiveZIP
		limits := d.ArchiveLimits
		if limits.MaxEntries == 0 {
			limits = securezip.DefaultLimits()
		}
		if _, err := securezip.Preflight(ctx, filePath, limits); err != nil {
			return result, err
		}
		if err := ctx.Err(); err != nil {
			return result, err
		}
		zipType, err := inspectZIP(ctx, filePath)
		if err != nil {
			result.Type = TypeArchiveZIP
			return result, err
		}
		if declaredMacro {
			zipType = TypeOfficeMacro
		}
		result.Type = zipType
		return result, ctx.Err()
	}

	if result.Type == TypeImagePNG || result.Type == TypeImageJPEG || result.Type == TypeImageWebP {
		maxPixels := d.MaxImagePixels
		if maxPixels == 0 {
			maxPixels = defaultMaxImagePixels
		}
		return result, validateImage(ctx, filePath, result.Type, maxPixels)
	}
	if result.Type != TypeUnknownBinary || textMIMEDenied(result.MIME) {
		return result, ctx.Err()
	}

	isText, err := validTextFile(ctx, filePath)
	if err != nil {
		return result, err
	}
	if isText {
		result.Type = textType(result.Extension)
	}
	return result, ctx.Err()
}

func typeFromMIME(mediaType string) Type {
	switch mediaType {
	case "application/pdf":
		return TypeDocumentPDF
	case "image/png":
		return TypeImagePNG
	case "image/jpeg", "image/jpg":
		return TypeImageJPEG
	case "image/webp":
		return TypeImageWebP
	case "application/zip", "application/x-zip", "application/x-zip-compressed":
		return TypeArchiveZIP
	case "application/vnd.ms-word.document.macroenabled.12",
		"application/vnd.ms-excel.sheet.macroenabled.12",
		"application/vnd.ms-powerpoint.presentation.macroenabled.12":
		return TypeOfficeMacro
	case "application/msword", "application/vnd.ms-word",
		"application/vnd.ms-excel", "application/vnd.ms-powerpoint",
		"application/vnd.ms-office", "application/x-ole-storage", "application/x-cdf", "application/cdfv2":
		return TypeLegacyOffice
	case "application/vnd.microsoft.portable-executable", "application/x-dosexec", "application/x-msdownload":
		return TypeExecutablePE
	case "application/x-executable", "application/x-pie-executable":
		return TypeExecutableELF
	case "application/x-mach-binary", "application/x-mach-o":
		return TypeExecutableMachO
	case "application/x-sharedlib", "application/x-mach-o-dylib", "application/x-archive":
		return TypeSharedLibrary
	case "application/x-object", "application/x-mach-o-object", "application/x-coff":
		return TypeObjectFile
	case "application/vnd.android.package-archive", "application/java-archive",
		"application/x-java-archive", "application/x-ios-app":
		return TypeApplicationPackage
	case "application/x-iso9660-image", "application/x-apple-diskimage",
		"application/x-raw-disk-image", "application/vnd.efi.iso":
		return TypeDiskImage
	default:
		return TypeUnknownBinary
	}
}

func isZIPMIME(mediaType string) bool {
	if typeFromMIME(mediaType) == TypeArchiveZIP {
		return true
	}
	switch mediaType {
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.ms-word.document.macroenabled.12",
		"application/vnd.ms-excel.sheet.macroenabled.12",
		"application/vnd.ms-powerpoint.presentation.macroenabled.12":
		return true
	default:
		return false
	}
}

func inspectZIP(ctx context.Context, filePath string) (Type, error) {
	reader, err := zip.OpenReader(filePath)
	if err != nil {
		return TypeArchiveZIP, nil
	}
	defer reader.Close()

	var roots, contentTypes int
	var macro, javaPackage, androidManifest, androidCode, appleApp bool
	for _, entry := range reader.File {
		if err := ctx.Err(); err != nil {
			return TypeArchiveZIP, err
		}
		name := entry.Name
		lowerName := strings.ToLower(strings.ReplaceAll(name, "\\", "/"))
		switch {
		case strings.HasPrefix(name, "word/"):
			roots |= 1
		case strings.HasPrefix(name, "xl/"):
			roots |= 2
		case strings.HasPrefix(name, "ppt/"):
			roots |= 4
		}
		if strings.EqualFold(path.Base(lowerName), "vbaproject.bin") {
			macro = true
		}
		switch {
		case strings.EqualFold(name, "META-INF/MANIFEST.MF"), strings.HasPrefix(name, "WEB-INF/"):
			javaPackage = true
		case name == "AndroidManifest.xml":
			androidManifest = true
		case name == "classes.dex":
			androidCode = true
		case strings.HasPrefix(name, "Payload/") && strings.Contains(name, ".app/"):
			appleApp = true
		}
		if name != "[Content_Types].xml" {
			continue
		}
		if entry.FileInfo().IsDir() {
			return TypeArchiveZIP, &securezip.Error{Code: securezip.CodeInvalid, Entry: name, Err: errors.New("content types entry is a directory")}
		}
		contentTypes++
		body, readErr := readZipFile(ctx, entry, maxContentTypesSize)
		if readErr != nil {
			return TypeArchiveZIP, fmt.Errorf("inspect OOXML content types: %w", readErr)
		}
		macro = macro || bytes.Contains(bytes.ToLower(body), []byte("macroenabled"))
	}

	if macro {
		return TypeOfficeMacro, nil
	}
	if javaPackage || (androidManifest && androidCode) || appleApp {
		return TypeApplicationPackage, nil
	}
	if contentTypes != 1 {
		return TypeArchiveZIP, nil
	}
	switch roots {
	case 1:
		return TypeDocumentDOCX, nil
	case 2:
		return TypeDocumentXLSX, nil
	case 4:
		return TypeDocumentPPTX, nil
	default:
		return TypeArchiveZIP, nil
	}
}

func readZipFile(ctx context.Context, entry *zip.File, limit int64) ([]byte, error) {
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	body, err := io.ReadAll(io.LimitReader(contextReader{ctx: ctx, reader: reader}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("entry exceeds %d bytes", limit)
	}
	return body, nil
}

func textType(extension string) Type {
	switch extension {
	case ".svg", ".rtf", ".html", ".htm", ".css":
		return TypeUnknownBinary
	case ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".java",
		".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".go", ".rs",
		".cs", ".kt", ".kts", ".swift", ".scala", ".rb", ".php", ".r",
		".m", ".lua", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd":
		return TypeTextSource
	case ".csv", ".tsv", ".json", ".jsonl", ".ndjson", ".yaml", ".yml",
		".xml", ".sql", ".ipynb", ".bib":
		return TypeTextData
	default:
		return TypeTextPlain
	}
}

func textMIMEDenied(mediaType string) bool {
	return strings.HasPrefix(mediaType, "image/") || strings.HasPrefix(mediaType, "audio/") ||
		strings.HasPrefix(mediaType, "video/") || strings.HasPrefix(mediaType, "font/") ||
		strings.HasPrefix(mediaType, "application/font") || strings.HasPrefix(mediaType, "application/x-font") ||
		mediaType == "application/rtf" || mediaType == "text/rtf" || mediaType == "text/html" ||
		mediaType == "text/css" || mediaType == "application/xhtml+xml" || mediaType == "application/postscript"
}

func validTextFile(ctx context.Context, filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	reader := bufio.NewReader(contextReader{ctx: ctx, reader: file})
	bom, _ := reader.Peek(2)
	if len(bom) == 2 && ((bom[0] == 0xff && bom[1] == 0xfe) || (bom[0] == 0xfe && bom[1] == 0xff)) {
		_, _ = reader.Discard(2)
		return validUTF16(reader, bom[0] == 0xff)
	}
	return validUTF8(reader)
}

func validUTF8(reader *bufio.Reader) (bool, error) {
	var runes, nuls uint64
	for {
		r, size, err := reader.ReadRune()
		if err == io.EOF {
			return lowNULCount(runes, nuls), nil
		}
		if err != nil {
			return false, err
		}
		if r == utf8.RuneError && size == 1 {
			return false, nil
		}
		runes++
		if r == 0 {
			nuls++
		}
	}
}

func validUTF16(reader io.Reader, littleEndian bool) (bool, error) {
	var runes, nuls uint64
	var pendingHigh uint16
	var pair [2]byte
	var order binary.ByteOrder = binary.BigEndian
	if littleEndian {
		order = binary.LittleEndian
	}
	for {
		_, err := io.ReadFull(reader, pair[:])
		if err == io.EOF {
			return pendingHigh == 0 && lowNULCount(runes, nuls), nil
		}
		if err == io.ErrUnexpectedEOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		unit := order.Uint16(pair[:])
		if pendingHigh != 0 {
			if unit < 0xdc00 || unit > 0xdfff || utf16.DecodeRune(rune(pendingHigh), rune(unit)) == utf8.RuneError {
				return false, nil
			}
			pendingHigh = 0
			runes++
			continue
		}
		if unit >= 0xd800 && unit <= 0xdbff {
			pendingHigh = unit
			continue
		}
		if unit >= 0xdc00 && unit <= 0xdfff {
			return false, nil
		}
		runes++
		if unit == 0 {
			nuls++
		}
	}
}

func lowNULCount(runes, nuls uint64) bool {
	return runes == 0 || nuls <= runes/100
}

func validateImage(ctx context.Context, filePath string, imageType Type, maxPixels uint64) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	var width, height int
	if imageType == TypeImageWebP {
		width, height, err = webPDimensions(ctx, file)
	} else {
		var config image.Config
		var format string
		config, format, err = image.DecodeConfig(contextReader{ctx: ctx, reader: file})
		width, height = config.Width, config.Height
		expected := "png"
		if imageType == TypeImageJPEG {
			expected = "jpeg"
		}
		if err == nil && format != expected {
			err = fmt.Errorf("unexpected format %q", format)
		}
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil || width <= 0 || height <= 0 {
		return fmt.Errorf("%w: %v", ErrInvalidImage, err)
	}
	if uint64(width) > maxPixels/uint64(height) {
		return fmt.Errorf("%w: %dx%d exceeds %d pixels", ErrImageDimensionsExceeded, width, height, maxPixels)
	}
	return nil
}

func webPDimensions(ctx context.Context, reader io.Reader) (int, int, error) {
	reader = contextReader{ctx: ctx, reader: reader}
	var header [20]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, 0, err
	}
	if string(header[0:4]) != "RIFF" || string(header[8:12]) != "WEBP" {
		return 0, 0, errors.New("invalid WebP header")
	}
	chunkSize := binary.LittleEndian.Uint32(header[16:20])
	var need int
	switch string(header[12:16]) {
	case "VP8X":
		need = 10
	case "VP8L":
		need = 5
	case "VP8 ":
		need = 10
	default:
		return 0, 0, errors.New("unsupported WebP chunk")
	}
	if chunkSize < uint32(need) {
		return 0, 0, errors.New("short WebP chunk")
	}
	payload := make([]byte, need)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, 0, err
	}

	switch string(header[12:16]) {
	case "VP8X":
		return 1 + int(payload[4]) + int(payload[5])<<8 + int(payload[6])<<16,
			1 + int(payload[7]) + int(payload[8])<<8 + int(payload[9])<<16, nil
	case "VP8L":
		if payload[0] != 0x2f {
			return 0, 0, errors.New("invalid VP8L signature")
		}
		return 1 + int(payload[1]) + int(payload[2]&0x3f)<<8,
			1 + int(payload[3])<<2 + int(payload[2]&0xc0)>>6 + int(payload[4]&0x0f)<<10, nil
	default:
		if !bytes.Equal(payload[3:6], []byte{0x9d, 0x01, 0x2a}) {
			return 0, 0, errors.New("invalid VP8 signature")
		}
		return int(binary.LittleEndian.Uint16(payload[6:8]) & 0x3fff),
			int(binary.LittleEndian.Uint16(payload[8:10]) & 0x3fff), nil
	}
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
