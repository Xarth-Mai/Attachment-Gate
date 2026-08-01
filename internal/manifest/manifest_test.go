package manifest

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestMarshalUsesArraysAndNullPaths(t *testing.T) {
	b, err := Marshal(Manifest{Files: []File{{Warnings: nil}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range [][]byte{[]byte(`"files": [`), []byte(`"output_path": null`), []byte(`"warnings": []`)} {
		if !bytes.Contains(b, want) {
			t.Fatalf("manifest missing %s:\n%s", want, b)
		}
	}
}

func FuzzManifestJSON(f *testing.F) {
	f.Add([]byte(`{"schema_version":1,"files":[]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var value Manifest
		if json.Unmarshal(data, &value) == nil {
			_, _ = Marshal(value)
		}
	})
}
