package manifest

import (
	"encoding/json"
	"time"
)

const SchemaVersion = 1

type Manifest struct {
	SchemaVersion int       `json:"schema_version"`
	ScanID        string    `json:"scan_id"`
	BatchID       string    `json:"batch_id"`
	Status        string    `json:"status"`
	Outcome       string    `json:"outcome"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	Policy        Policy    `json:"policy"`
	Engines       Engines   `json:"engines"`
	Summary       Summary   `json:"summary"`
	Files         []File    `json:"files"`
}

type Policy struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}

type Engines struct {
	TypeDetector Engine         `json:"type_detector"`
	Malware      *MalwareEngine `json:"malware,omitempty"`
}

type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type MalwareEngine struct {
	Name            string `json:"name"`
	EngineVersion   string `json:"engine_version"`
	DatabaseVersion string `json:"database_version"`
	DatabaseTime    string `json:"database_time"`
}

type Summary struct {
	UploadedFiles   int   `json:"uploaded_files"`
	DiscoveredFiles int   `json:"discovered_files"`
	ApprovedFiles   int   `json:"approved_files"`
	RejectedFiles   int   `json:"rejected_files"`
	ApprovedBytes   int64 `json:"approved_bytes"`
}

type File struct {
	ID           string    `json:"id"`
	ParentID     *string   `json:"parent_id"`
	AttachmentID string    `json:"attachment_id"`
	SourcePath   string    `json:"source_path"`
	OutputPath   *string   `json:"output_path"`
	Origin       string    `json:"origin"`
	Kind         string    `json:"kind"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	Detected     Detected  `json:"detected"`
	Decision     string    `json:"decision"`
	Action       string    `json:"action"`
	Reason       *Reason   `json:"reason,omitempty"`
	Warnings     []Warning `json:"warnings"`
}

type Detected struct {
	Type      string `json:"type"`
	MIME      string `json:"mime"`
	Extension string `json:"extension"`
}

type Reason struct {
	Code   string `json:"code"`
	Entry  string `json:"entry,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type Warning struct {
	Code               string   `json:"code"`
	DeclaredExtension  string   `json:"declared_extension,omitempty"`
	ExpectedExtensions []string `json:"expected_extensions,omitempty"`
}

func Marshal(m Manifest) ([]byte, error) {
	if m.Files == nil {
		m.Files = []File{}
	}
	for i := range m.Files {
		if m.Files[i].Warnings == nil {
			m.Files[i].Warnings = []Warning{}
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
