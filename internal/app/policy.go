package app

import (
	"path"
	"slices"
	"strings"

	"github.com/Xarth-Mai/Attachment-Gate/internal/detect"
	"github.com/Xarth-Mai/Attachment-Gate/internal/manifest"
)

func isExecutableType(kind detect.Type) bool {
	switch kind {
	case detect.TypeExecutablePE, detect.TypeExecutableELF, detect.TypeExecutableMachO,
		detect.TypeSharedLibrary, detect.TypeObjectFile, detect.TypeApplicationPackage,
		detect.TypeDiskImage:
		return true
	default:
		return false
	}
}

func warningFor(result detect.Result, allowed map[string]bool) *manifest.Warning {
	switch result.Type {
	case detect.TypeOfficeMacro:
		return &manifest.Warning{Code: "office_macro_found", DeclaredExtension: result.Extension}
	case detect.TypeLegacyOffice:
		return &manifest.Warning{Code: "legacy_office_found", DeclaredExtension: result.Extension}
	case detect.TypeUnknownBinary:
		if strings.HasPrefix(result.MIME, "text/") || result.MIME == "application/json" || result.MIME == "application/xml" {
			return &manifest.Warning{Code: "invalid_text_encoding", DeclaredExtension: result.Extension}
		}
		return &manifest.Warning{Code: "unknown_type", DeclaredExtension: result.Extension}
	}
	if !allowed[string(result.Type)] {
		return &manifest.Warning{Code: "type_not_allowed", DeclaredExtension: result.Extension}
	}
	return nil
}

func extensionWarning(result detect.Result) *manifest.Warning {
	if result.Extension == "" {
		return nil
	}
	expected := expectedExtensions(result)
	if len(expected) == 0 || slices.Contains(expected, strings.ToLower(result.Extension)) {
		return nil
	}
	return &manifest.Warning{
		Code:               "extension_mismatch",
		DeclaredExtension:  result.Extension,
		ExpectedExtensions: expected,
	}
}

func expectedExtensions(result detect.Result) []string {
	switch result.Type {
	case detect.TypeDocumentPDF:
		return []string{".pdf"}
	case detect.TypeDocumentDOCX:
		return []string{".docx"}
	case detect.TypeDocumentXLSX:
		return []string{".xlsx"}
	case detect.TypeDocumentPPTX:
		return []string{".pptx"}
	case detect.TypeImagePNG:
		return []string{".png"}
	case detect.TypeImageJPEG:
		return []string{".jpg", ".jpeg"}
	case detect.TypeImageWebP:
		return []string{".webp"}
	case detect.TypeArchiveZIP:
		return []string{".zip"}
	case detect.TypeTextSource, detect.TypeTextData:
		return []string{result.Extension}
	case detect.TypeTextPlain:
		return []string{".txt", ".md", ".markdown", ".rst", ".tex"}
	default:
		return nil
	}
}

func nestedArchive(result detect.Result) bool {
	if result.Type == detect.TypeArchiveZIP || result.Type == detect.TypeApplicationPackage {
		return true
	}
	return unsupportedArchiveMIME(result.MIME)
}

func unsupportedArchiveMIME(mime string) bool {
	switch mime {
	case "application/gzip", "application/x-gzip", "application/x-7z-compressed",
		"application/vnd.rar", "application/x-rar", "application/x-rar-compressed",
		"application/x-tar", "application/x-bzip2", "application/x-xz":
		return true
	default:
		return false
	}
}

func excludedPath(name string, directoryNames, fileNames, extensions []string) string {
	parts := strings.Split(name, "/")
	for _, component := range parts[:len(parts)-1] {
		if containsFold(directoryNames, component) {
			return "excluded_path"
		}
	}
	base := parts[len(parts)-1]
	if containsFold(fileNames, base) || containsFold(extensions, path.Ext(base)) {
		return "secret_file_not_allowed"
	}
	return ""
}

func containsFold(values []string, value string) bool {
	for _, candidate := range values {
		if strings.EqualFold(candidate, value) {
			return true
		}
	}
	return false
}
