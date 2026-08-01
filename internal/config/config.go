package config

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

const (
	SchemaVersion      = 1
	HardMaxFileSize    = ByteSize(200 << 20)
	HardMaxExtracted   = ByteSize(1 << 30)
	HardMaxFileCount   = 10_000
	maxConfigFileBytes = 1 << 20
)

// ByteSize is a byte count decoded from values such as 50MiB.
type ByteSize int64

func ParseByteSize(value string) (ByteSize, error) {
	value = strings.TrimSpace(value)
	i := 0
	for i < len(value) && value[i] >= '0' && value[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, fmt.Errorf("invalid byte size %q", value)
	}

	multiplier := int64(1)
	switch strings.ToLower(value[i:]) {
	case "", "b":
	case "kb":
		multiplier = 1_000
	case "kib":
		multiplier = 1 << 10
	case "mb":
		multiplier = 1_000_000
	case "mib":
		multiplier = 1 << 20
	case "gb":
		multiplier = 1_000_000_000
	case "gib":
		multiplier = 1 << 30
	case "tb":
		multiplier = 1_000_000_000_000
	case "tib":
		multiplier = 1 << 40
	default:
		return 0, fmt.Errorf("invalid byte size unit in %q", value)
	}

	n, err := strconv.ParseInt(value[:i], 10, 64)
	if err != nil || n > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("byte size %q overflows", value)
	}
	return ByteSize(n * multiplier), nil
}

func (b *ByteSize) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("byte size must be a scalar")
	}
	value, err := ParseByteSize(node.Value)
	if err != nil {
		return err
	}
	*b = value
	return nil
}

func (b ByteSize) String() string {
	for _, unit := range []struct {
		name string
		size ByteSize
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if b >= unit.size && b%unit.size == 0 {
			return fmt.Sprintf("%d%s", b/unit.size, unit.name)
		}
	}
	return fmt.Sprintf("%dB", b)
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar")
	}
	value, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	*d = Duration(value)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

type Mode uint32

func (m *Mode) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("mode must be a scalar")
	}
	value := strings.TrimPrefix(node.Value, "0o")
	parsed, err := strconv.ParseUint(value, 8, 9)
	if err != nil || parsed > 0o777 {
		return fmt.Errorf("invalid permission mode %q", node.Value)
	}
	*m = Mode(parsed)
	return nil
}

func (m Mode) FileMode() os.FileMode { return os.FileMode(m) }
func (m Mode) String() string        { return fmt.Sprintf("%04o", uint32(m)) }

type Config struct {
	SchemaVersion int      `yaml:"schema_version"`
	Profile       Profile  `yaml:"profile"`
	Roots         Roots    `yaml:"roots"`
	Limits        Limits   `yaml:"limits"`
	Archives      Archives `yaml:"archives"`
	Malware       Malware  `yaml:"malware"`
	Policy        Policy   `yaml:"policy"`
	AllowedTypes  []string `yaml:"allowed_types"`
	Paths         Paths    `yaml:"paths"`
	Output        Output   `yaml:"output"`
}

type Profile struct {
	Name    string `yaml:"name"`
	Version int    `yaml:"version"`
}

type Roots struct {
	Quarantine string `yaml:"quarantine"`
	Results    string `yaml:"results"`
}

type Limits struct {
	MaxInputFiles         int      `yaml:"max_input_files"`
	MaxInputFileSize      ByteSize `yaml:"max_input_file_size"`
	MaxInputTotalSize     ByteSize `yaml:"max_input_total_size"`
	MaxDiscoveredFiles    int      `yaml:"max_discovered_files"`
	MaxExtractedFileSize  ByteSize `yaml:"max_extracted_file_size"`
	MaxExtractedTotalSize ByteSize `yaml:"max_extracted_total_size"`
	MaxArchiveEntries     int      `yaml:"max_archive_entries"`
	MaxCompressionRatio   uint64   `yaml:"max_compression_ratio"`
	MaxPathDepth          int      `yaml:"max_path_depth"`
	MaxRelativePathBytes  int      `yaml:"max_relative_path_bytes"`
	MaxImagePixels        uint64   `yaml:"max_image_pixels"`
	BatchTimeout          Duration `yaml:"batch_timeout"`
	FileScanTimeout       Duration `yaml:"file_scan_timeout"`
}

type Archives struct {
	Enabled          bool     `yaml:"enabled"`
	AllowedFormats   []string `yaml:"allowed_formats"`
	NestedArchive    string   `yaml:"nested_archive"`
	EncryptedArchive string   `yaml:"encrypted_archive"`
	UnsafePath       string   `yaml:"unsafe_path"`
	MalformedArchive string   `yaml:"malformed_archive"`
}

type Malware struct {
	Enabled        bool     `yaml:"enabled"`
	Required       bool     `yaml:"required"`
	Socket         string   `yaml:"socket"`
	MaxDatabaseAge Duration `yaml:"max_database_age"`
}

type Policy struct {
	UnknownType       string `yaml:"unknown_type"`
	DetectorError     string `yaml:"detector_error"`
	ExtensionMismatch string `yaml:"extension_mismatch"`
	MalwareScanError  string `yaml:"malware_scan_error"`
	OfficeMacros      string `yaml:"office_macros"`
	LegacyOffice      string `yaml:"legacy_office"`
}

type Paths struct {
	ExcludeDirectoryNames []string `yaml:"exclude_directory_names"`
	ExcludeFileNames      []string `yaml:"exclude_file_names"`
	ExcludeExtensions     []string `yaml:"exclude_extensions"`
}

type Output struct {
	FileMode                   Mode `yaml:"file_mode"`
	DirectoryMode              Mode `yaml:"directory_mode"`
	PreserveTimestamps         bool `yaml:"preserve_timestamps"`
	PreservePermissions        bool `yaml:"preserve_permissions"`
	PreserveExtendedAttributes bool `yaml:"preserve_extended_attributes"`
}

func Default() Config {
	return Config{
		SchemaVersion: SchemaVersion,
		Profile:       Profile{Name: "attachment-gate-v1", Version: 1},
		Roots: Roots{
			Quarantine: "/var/lib/attachment-gate/quarantine",
			Results:    "/var/lib/attachment-gate/results",
		},
		Limits: Limits{
			MaxInputFiles:         20,
			MaxInputFileSize:      50 << 20,
			MaxInputTotalSize:     100 << 20,
			MaxDiscoveredFiles:    2_000,
			MaxExtractedFileSize:  50 << 20,
			MaxExtractedTotalSize: 300 << 20,
			MaxArchiveEntries:     2_000,
			MaxCompressionRatio:   200,
			MaxPathDepth:          20,
			MaxRelativePathBytes:  512,
			MaxImagePixels:        40_000_000,
			BatchTimeout:          Duration(120 * time.Second),
			FileScanTimeout:       Duration(30 * time.Second),
		},
		Archives: Archives{
			Enabled:          true,
			AllowedFormats:   []string{"zip"},
			NestedArchive:    "reject_entry",
			EncryptedArchive: "reject_container",
			UnsafePath:       "reject_container",
			MalformedArchive: "reject_container",
		},
		Malware: Malware{
			Enabled:        true,
			Required:       true,
			Socket:         "unix:///run/clamav/clamd.sock",
			MaxDatabaseAge: Duration(72 * time.Hour),
		},
		Policy: Policy{
			UnknownType:       "reject",
			DetectorError:     "reject_file",
			ExtensionMismatch: "warn",
			MalwareScanError:  "reject_batch",
			OfficeMacros:      "reject",
			LegacyOffice:      "reject",
		},
		AllowedTypes: []string{
			"document_pdf", "document_docx", "document_xlsx", "document_pptx",
			"text_plain", "text_source", "text_data",
			"image_png", "image_jpeg", "image_webp", "archive_zip",
		},
		Paths: Paths{
			ExcludeDirectoryNames: []string{
				".git", ".svn", ".hg", "node_modules", ".venv", "venv",
				"__pycache__", "target", "dist", "build", ".idea", ".vscode",
			},
			ExcludeFileNames: []string{
				".env", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
				"credentials.json", "service-account.json",
			},
			ExcludeExtensions: []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"},
		},
		Output: Output{FileMode: 0o440, DirectoryMode: 0o550},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(data) > maxConfigFileBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", maxConfigFileBytes)
	}
	return Parse(data)
}

func Parse(data []byte) (*Config, error) {
	cfg := Default()
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil && err != io.EOF {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode config: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if c.Profile.Name == "" || hasControl(c.Profile.Name) || c.Profile.Version <= 0 {
		return fmt.Errorf("profile name and version are required")
	}
	if err := validateRoot("roots.quarantine", c.Roots.Quarantine); err != nil {
		return err
	}
	if err := validateRoot("roots.results", c.Roots.Results); err != nil {
		return err
	}
	if pathsOverlap(c.Roots.Quarantine, c.Roots.Results) {
		return fmt.Errorf("roots.quarantine and roots.results must not overlap")
	}
	if err := c.Limits.validate(); err != nil {
		return err
	}
	if err := c.Archives.validate(); err != nil {
		return err
	}
	if err := c.Malware.validate(); err != nil {
		return err
	}
	if err := c.Policy.validate(); err != nil {
		return err
	}
	if err := validateAllowedTypes(c.AllowedTypes); err != nil {
		return err
	}
	if err := c.Paths.validate(); err != nil {
		return err
	}
	return c.Output.validate()
}

func (l Limits) validate() error {
	if l.MaxInputFiles <= 0 || l.MaxInputFileSize <= 0 || l.MaxInputTotalSize <= 0 ||
		l.MaxDiscoveredFiles <= 0 || l.MaxExtractedFileSize <= 0 || l.MaxExtractedTotalSize <= 0 ||
		l.MaxArchiveEntries <= 0 || l.MaxCompressionRatio == 0 || l.MaxPathDepth <= 0 || l.MaxRelativePathBytes <= 0 ||
		l.MaxImagePixels == 0 || l.BatchTimeout <= 0 || l.FileScanTimeout <= 0 {
		return fmt.Errorf("all limits must be finite and greater than zero")
	}
	if l.MaxInputFileSize > HardMaxFileSize || l.MaxExtractedFileSize > HardMaxFileSize {
		return fmt.Errorf("per-file limits must not exceed %s", HardMaxFileSize)
	}
	if l.MaxExtractedTotalSize > HardMaxExtracted {
		return fmt.Errorf("max_extracted_total_size must not exceed %s", HardMaxExtracted)
	}
	if l.MaxInputFiles > HardMaxFileCount || l.MaxDiscoveredFiles > HardMaxFileCount || l.MaxArchiveEntries > HardMaxFileCount {
		return fmt.Errorf("file count limits must not exceed %d", HardMaxFileCount)
	}
	if l.MaxInputFileSize > l.MaxInputTotalSize {
		return fmt.Errorf("max_input_file_size must not exceed max_input_total_size")
	}
	if l.MaxExtractedFileSize > l.MaxExtractedTotalSize {
		return fmt.Errorf("max_extracted_file_size must not exceed max_extracted_total_size")
	}
	return nil
}

func (a Archives) validate() error {
	if a.Enabled && len(a.AllowedFormats) == 0 {
		return fmt.Errorf("archives.allowed_formats is required when archives are enabled")
	}
	seen := make(map[string]struct{}, len(a.AllowedFormats))
	for _, format := range a.AllowedFormats {
		if format != "zip" {
			return fmt.Errorf("unsupported archive format %q", format)
		}
		if _, duplicate := seen[format]; duplicate {
			return fmt.Errorf("duplicate archive format %q", format)
		}
		seen[format] = struct{}{}
	}
	if a.NestedArchive != "reject_entry" || a.EncryptedArchive != "reject_container" ||
		a.UnsafePath != "reject_container" || a.MalformedArchive != "reject_container" {
		return fmt.Errorf("archive handling modes must use the schema v1 reject modes")
	}
	return nil
}

func (m Malware) validate() error {
	if !m.Enabled || !m.Required {
		return fmt.Errorf("malware scanning must be enabled and required")
	}
	if m.MaxDatabaseAge <= 0 || m.MaxDatabaseAge > Duration(72*time.Hour) {
		return fmt.Errorf("malware.max_database_age must be greater than zero and no more than 72h")
	}
	if err := validateUnixSocketURL(m.Socket); err != nil {
		return fmt.Errorf("malware.socket: %w", err)
	}
	return nil
}

func (p Policy) validate() error {
	if p.UnknownType != "reject" || p.OfficeMacros != "reject" || p.LegacyOffice != "reject" {
		return fmt.Errorf("unknown, macro, and legacy document policies must reject")
	}
	if !oneOf(p.DetectorError, "reject", "reject_file", "reject_batch") {
		return fmt.Errorf("invalid policy.detector_error %q", p.DetectorError)
	}
	if !oneOf(p.ExtensionMismatch, "warn", "reject") {
		return fmt.Errorf("invalid policy.extension_mismatch %q", p.ExtensionMismatch)
	}
	if !oneOf(p.MalwareScanError, "reject", "reject_file", "reject_batch") {
		return fmt.Errorf("invalid policy.malware_scan_error %q", p.MalwareScanError)
	}
	return nil
}

func (p Paths) validate() error {
	if err := validateNames("paths.exclude_directory_names", p.ExcludeDirectoryNames); err != nil {
		return err
	}
	if err := validateNames("paths.exclude_file_names", p.ExcludeFileNames); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(p.ExcludeExtensions))
	for _, extension := range p.ExcludeExtensions {
		if len(extension) < 2 || extension[0] != '.' || strings.ContainsAny(extension, `/\`) || hasControl(extension) {
			return fmt.Errorf("invalid paths.exclude_extensions entry %q", extension)
		}
		key := strings.ToLower(extension)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("duplicate paths.exclude_extensions entry %q", extension)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (o Output) validate() error {
	fileMode, directoryMode := os.FileMode(o.FileMode), os.FileMode(o.DirectoryMode)
	if fileMode == 0 || fileMode&0o333 != 0 || fileMode&0o400 == 0 {
		return fmt.Errorf("output.file_mode must grant the owner read-only access")
	}
	if directoryMode == 0 || directoryMode&0o222 != 0 || directoryMode&0o500 != 0o500 {
		return fmt.Errorf("output.directory_mode must grant the owner read-only traversal")
	}
	for shift := 0; shift <= 6; shift += 3 {
		fileClass := fileMode >> shift & 7
		directoryClass := directoryMode >> shift & 7
		if directoryClass != 0 && directoryClass != 5 || fileClass == 4 && directoryClass != 5 {
			return fmt.Errorf("output modes must grant matching read and directory traversal permissions")
		}
	}
	if o.PreserveTimestamps || o.PreservePermissions || o.PreserveExtendedAttributes {
		return fmt.Errorf("preserving timestamps, permissions, or extended attributes is not allowed")
	}
	return nil
}

func validateRoot(name, path string) error {
	if path == "" || hasControl(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return fmt.Errorf("%s must be an absolute, clean, non-root path", name)
	}
	return nil
}

func pathsOverlap(a, b string) bool {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func validateUnixSocketURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "unix" || parsed.Host != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || !strings.HasPrefix(value, "unix://") {
		return fmt.Errorf("must be a unix:///absolute/path URL")
	}
	if parsed.RawPath != "" || strings.Contains(value, "%") {
		return fmt.Errorf("escaped socket paths are not allowed")
	}
	if err := validateRoot("socket path", parsed.Path); err != nil {
		return err
	}
	return nil
}

func validateAllowedTypes(values []string) error {
	allowed := map[string]struct{}{
		"document_pdf": {}, "document_docx": {}, "document_xlsx": {}, "document_pptx": {},
		"text_plain": {}, "text_source": {}, "text_data": {}, "image_png": {},
		"image_jpeg": {}, "image_webp": {}, "archive_zip": {},
	}
	if len(values) == 0 {
		return fmt.Errorf("allowed_types must not be empty")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return fmt.Errorf("unsupported allowed type %q", value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate allowed type %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateNames(field string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || value == "." || value == ".." || filepath.Base(value) != value ||
			strings.ContainsAny(value, `/\`) || hasControl(value) {
			return fmt.Errorf("invalid %s entry %q", field, value)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("duplicate %s entry %q", field, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func hasControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
