package app

import (
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

func outputName(name string, maxBytes int) string {
	name = path.Base(strings.ReplaceAll(name, "\\", "/"))
	name = norm.NFC.String(name)
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '/' || r == '\\' {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." {
		name = "attachment"
	}
	if len(name) <= maxBytes {
		return name
	}
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if len(ext) >= maxBytes/2 {
		ext = ""
	}
	name = trimUTF8(base, maxBytes-len(ext)) + ext
	if name == "" || name == "." || name == ".." {
		return "attachment"
	}
	return name
}

func trimUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	for len(s) > n {
		_, size := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-size]
	}
	return s
}

func archiveDirectory(name string) string {
	name = outputName(name, 200)
	ext := filepath.Ext(name)
	if strings.EqualFold(ext, ".zip") {
		name = strings.TrimSuffix(name, ext)
	}
	if name == "" {
		return "archive"
	}
	return name
}
