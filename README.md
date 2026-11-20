# sbom.py

> Scan a folder and write a software bill of materials (SBOM) as `sbom.json`, in CycloneDX 1.6 JSON.

It finds the dependency manifests and lock files in a folder and its subfolders, and lists every package with its version and a [package URL (purl)](https://github.com/package-url/purl-spec). One file, Python standard library only, no installs.

## Requirements

- Python 3.11+

## Setup

1. Clone the repo, or download `sbom.py`.
2. That's it: there are no tokens, settings or packages to install.

## Usage

```bash
python sbom.py path/to/project
```

This writes `path/to/project/sbom.json`. To write it somewhere else:

```bash
python sbom.py path/to/project -o reports/sbom.json
```

With no folder, it scans the current one.

### What it reads

| Ecosystem | Files |
|---|---|
| Python | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `uv.lock` |
| JavaScript | `package-lock.json`, `package.json` |
| Ruby | `Gemfile.lock` |
| Go | `go.mod` |
| Rust | `Cargo.lock` |
| PHP | `composer.lock` |
| Swift | `Package.resolved` (Swift Package Manager and Xcode) |
| CocoaPods | `Podfile.lock` |

Where a lock file sits next to its manifest (`package-lock.json` beside `package.json`, or `poetry.lock` or `uv.lock` beside `pyproject.toml`), only the lock file is read, because it holds the exact versions. A package with no pinned version is listed without one.

It skips `.git`, `node_modules`, virtual environments, `vendor`, `Pods`, build output and similar folders. A file it can't read is reported and skipped, and the scan carries on.

Each component records the files it was found in, as `sbom:source` properties, so a package used in two places is listed once.

### In GitHub Actions

```yaml
- uses: actions/checkout@v7
- run: curl -sSLO https://raw.githubusercontent.com/SecOpsNews/script_sbom.py/main/sbom.py
- run: python sbom.py . -o sbom.json
- uses: actions/upload-artifact@v7
  with:
      name: sbom
      path: sbom.json
```

### What it doesn't do

It reads what your manifests and lock files declare. It doesn't inspect installed packages, container images or binaries, and it doesn't look up vulnerabilities. To check the SBOM for known CVEs, feed it to a scanner such as [OSV-Scanner](https://github.com/google/osv-scanner) or [Grype](https://github.com/anchore/grype).

## Testing

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest tests
```

## Changes and Release

Increment the `package.json` version, using SemVer, when committing changes to the script, and keep `VERSION` in `sbom.py` in step. The GitHub action creates a new release using the last commit message as the release note.

## Notes

Made by [thechelsuk](https://thechels.uk) for [SecOpsNews](https://secops.thechels.uk): security news, advisories and critical CVEs on one dashboard. MIT licensed: see [LICENSE](LICENSE).
