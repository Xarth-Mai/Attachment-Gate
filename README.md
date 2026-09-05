# Attachment Gate

Current version: `0.1.5`. Manifest schema: v1.

Attachment Gate is a small Go CLI that turns an untrusted upload batch into a read-only set of approved files plus an auditable JSON manifest. It verifies declared sizes and hashes, detects real file types with libmagic, scans with ClamAV, and safely expands ZIP files.

Approval means that a file passed the configured file-level policy. It is not proof that the content is true, harmless to every parser, or safe to execute.

## Requirements

- Go 1.24 or newer
- `file` with a working libmagic database
- `clamd` on a local Unix socket with current signatures

Build and test:

```sh
go build -o attachment-gate ./cmd/attachment-gate
go test ./...
```

## Input and output

Each input batch is a direct child of the configured quarantine root:

```text
<batch-id>/
├── upload.json
└── blobs/
    ├── <opaque-blob-name>
    └── <opaque-blob-name>
```

`upload.json` uses schema version 1 and declares every blob:

```json
{
  "schema_version": 1,
  "batch_id": "batch-01",
  "files": [{
    "attachment_id": "attachment-01",
    "blob_name": "0198d6cc.bin",
    "original_name": "notes.md",
    "declared_content_type": "text/markdown",
    "uploaded_size": 123,
    "uploaded_sha256": "<64 hexadecimal characters>"
  }]
}
```

Freeze the batch before scanning: stop all writers and make blobs read-only. Extra files, links, special files, or metadata mismatches reject the batch.

A successful scan atomically publishes:

```text
<batch-id>/
├── approved/
└── manifest.json
```

Only `approved/` should be exposed downstream. The caller owns quarantine retention and deletion.

## Usage

Start from [configs/attachment-gate-v1.yaml](configs/attachment-gate-v1.yaml), set both roots, and keep the ClamAV socket local:

```sh
attachment-gate doctor --config /etc/attachment-gate/v1.yaml

attachment-gate policy --config /etc/attachment-gate/v1.yaml

attachment-gate scan \
  --input /var/lib/attachment-gate/quarantine/batch-01 \
  --output /var/lib/attachment-gate/results/batch-01 \
  --config /etc/attachment-gate/v1.yaml

attachment-gate version
```

`policy` prints canonical JSON containing the tool version, profile name and version, and the same effective configuration SHA-256 written into scan manifests.

`scan` is quiet by default; `--verbose` writes file IDs and decisions to stderr without file contents. The manifest is the business result. Exit `0` includes `all_approved`, `partial`, and `none_approved` outcomes.

| Exit | Meaning |
| ---: | --- |
| 0 | Scan completed |
| 2 | Arguments or configuration invalid |
| 3 | Input batch invalid |
| 4 | Required detector or malware scanner unavailable |
| 5 | Output filesystem failure |
| 6 | Canceled or timed out |
| 70 | Internal error |

## v1 policy

The shipped profile allows PDF, non-macro DOCX/XLSX/PPTX, UTF-8 or BOM-marked UTF-16 text and source, PNG/JPEG/WebP, and classic ZIP. It rejects ZIP64 and other archive formats, executables, libraries, application packages, disk images, legacy or macro-enabled office files, SVG, media, fonts, unknown binary data, encrypted ZIPs, nested archives, unsafe paths, links, special files, and configured secret/build paths.

ZIP extraction has independent limits for entries, paths, declared sizes, actual bytes, compression ratio, depth, and time. Files are created with `O_EXCL`, permissions and timestamps are discarded, and the final result is published by atomic rename. Safety ceilings, traversal checks, link rejection, byte limits, and read-only output cannot be disabled by configuration.

This v1 intentionally has no service mode, plugin system, recursive archive support, content rewriting, or document execution.

## License

[Mozilla Public License 2.0](LICENSE).
