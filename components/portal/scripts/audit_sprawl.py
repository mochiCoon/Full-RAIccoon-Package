#!/usr/bin/env python3
"""Non-destructive portal sprawl audit.

Prints a concise inventory of source files, runtime data, generated reports,
and root scratch files. It never deletes or moves data.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_TOP = {".git", ".venv", "__pycache__", ".pytest_cache"}
ROOT_ALLOWED = {
    ".env.example",
    ".gitignore",
    "README.md",
    "app.py",
    "requirements.txt",
}
ROOT_ALLOWED_DIRS = {"data", "deploy", "docs", "scripts", "static", "templates", "tests"}


def iter_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if rel.parts and rel.parts[0] in SKIP_TOP:
            continue
        if path.is_file():
            files.append(path)
    return files


def main() -> int:
    files = iter_files()
    by_top = Counter(path.relative_to(ROOT).parts[0] for path in files)
    suffixes = Counter(path.suffix.lower() or "[none]" for path in files)
    generated = [p for p in files if "generated-report-sources" in p.parts]
    generated_final = [p for p in generated if "final" in p.parts]
    portal_docs = [p for p in files if "Reports" in p.parts]
    root_files = [p for p in ROOT.iterdir() if p.is_file() and p.name not in ROOT_ALLOWED]
    root_dirs = [p for p in ROOT.iterdir() if p.is_dir() and p.name not in ROOT_ALLOWED_DIRS and p.name not in SKIP_TOP]

    print(f"Portal root: {ROOT}")
    print(f"Files excluding git/venv/cache: {len(files)}")
    print("\nTop-level distribution:")
    for name, count in by_top.most_common():
        print(f"  {name}: {count}")

    print("\nHigh-signal generated/runtime areas:")
    print(f"  generated-report-sources files: {len(generated)}")
    print(f"  generated final artifacts: {len(generated_final)}")
    print(f"  portal Reports mirror files: {len(portal_docs)}")
    print(f"  PDFs in tree: {suffixes['.pdf']}")
    print(f"  DOCX in tree: {suffixes['.docx']}")
    print(f"  TXT in tree: {suffixes['.txt']}")

    print("\nRoot clutter check:")
    if not root_files and not root_dirs:
        print("  OK: no unexpected root files/directories")
    else:
        for path in root_files:
            print(f"  unexpected file: {path.name}")
        for path in root_dirs:
            print(f"  unexpected dir: {path.name}/")

    print("\nRule of thumb: move temporary local artifacts to data/local-scratch/<purpose>/; do not delete generated report data without a link audit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
