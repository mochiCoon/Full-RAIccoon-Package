---
name: raiccoon-opencti-ingestion
description: Publish finalized reports into OpenCTI while keeping local metadata clean.
---
# RAIccoon OpenCTI ingestion

Use this skill when uploading final reports to OpenCTI.

Pattern:
1. Require a finalized report directory with `metadata.yaml`, `report.md`, and final PDF.
2. Keep visible report type separate from OpenCTI classification.
3. Use stable report IDs so reruns update rather than duplicate.
4. Verify returned OpenCTI IDs directly, not via fuzzy search.
5. Confirm content, attachment, marking, and linked objects after upload.
