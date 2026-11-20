import argparse
import json
import os
import re
import sys
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

VERSION = "1.0.0"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", "vendor", "Pods", "Carthage", "DerivedData", ".build", "dist", "build", "target",
    ".jekyll-cache", "_site",
}

REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:===?\s*([^\s;,]+))?")


def pypi(name, version=None):
    return component("pypi", re.sub(r"[-_.]+", "-", name).lower(), version)


def component(kind, name, version=None):
    purl = f"pkg:{kind}/{name}" + (f"@{version}" if version else "")
    item = {"type": "library", "name": name.rsplit("/", 1)[-1] if kind == "npm" else name, "purl": purl}
    if kind == "npm" and name.startswith("%40"):
        item["name"] = name.replace("%40", "@", 1)
    if version:
        item["version"] = version
    return item


def npm(name, version=None):
    return component("npm", quote(name, safe="/"), version)


def parse_requirement(spec):
    spec = spec.split(";", 1)[0].strip()
    if not spec or spec.startswith(("-", "#")) or "://" in spec:
        return None
    match = REQUIREMENT.match(spec)
    if not match:
        return None
    version = match.group(2) if re.search(r"(^|[^<>!~])==", spec) else None
    return pypi(match.group(1), version)


def read_requirements(path):
    items = []
    for line in path.read_text().splitlines():
        item = parse_requirement(line.split(" #", 1)[0])
        if item:
            items.append(item)
    return items


def read_pyproject(path):
    if (path.parent / "poetry.lock").exists() or (path.parent / "uv.lock").exists():
        return []
    data = tomllib.loads(path.read_text())
    items = [parse_requirement(d) for d in data.get("project", {}).get("dependencies", [])]
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    items += [pypi(name) for name in poetry if name.lower() != "python"]
    return [i for i in items if i]


def read_python_lock(path):
    items = []
    for package in tomllib.loads(path.read_text()).get("package", []):
        source = package.get("source", {})
        if isinstance(source, dict) and ("editable" in source or "virtual" in source):
            continue
        items.append(pypi(package["name"], package.get("version")))
    return items


def read_package_lock(path):
    data = json.loads(path.read_text())
    items = []
    if "packages" in data:
        for key, package in data["packages"].items():
            if "node_modules/" not in key or package.get("link"):
                continue
            items.append(npm(key.rsplit("node_modules/", 1)[1], package.get("version")))
        return items

    def walk(dependencies):
        for name, package in (dependencies or {}).items():
            items.append(npm(name, package.get("version")))
            walk(package.get("dependencies"))

    walk(data.get("dependencies"))
    return items


def read_package_json(path):
    if (path.parent / "package-lock.json").exists():
        return []
    data = json.loads(path.read_text())
    items = []
    for group in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(group) or {}).items():
            exact = spec if re.fullmatch(r"\d+\.\d+\.\d+[\w.+-]*", str(spec)) else None
            items.append(npm(name, exact))
    return items


def read_gemfile_lock(path):
    items, in_specs = [], False
    for line in path.read_text().splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and not line.startswith("  "):
            in_specs = False
        match = re.match(r"^    ([^\s(]+) \(([^)]+)\)$", line) if in_specs else None
        if match:
            items.append(component("gem", match.group(1), match.group(2)))
    return items


def read_go_mod(path):
    items, in_block = [], False
    for raw in path.read_text().splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):]
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2:
            items.append(component("golang", parts[0], parts[1]))
    return items


def read_cargo_lock(path):
    return [
        component("cargo", p["name"], p.get("version"))
        for p in tomllib.loads(path.read_text()).get("package", [])
        if p.get("source")
    ]


def read_composer_lock(path):
    data = json.loads(path.read_text())
    return [
        component("composer", p["name"], p.get("version"))
        for group in ("packages", "packages-dev")
        for p in data.get(group) or []
    ]


def swift_name(url):
    name = re.sub(r"^[a-z]+://", "", url)
    name = re.sub(r"^git@([^:]+):", r"\1/", name)
    return re.sub(r"\.git$", "", name).rstrip("/")


def read_package_resolved(path):
    data = json.loads(path.read_text())
    pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
    items = []
    for pin in pins:
        url = pin.get("location") or pin.get("repositoryURL") or pin.get("identity") or pin.get("package")
        version = (pin.get("state") or {}).get("version") or (pin.get("state") or {}).get("revision")
        items.append(component("swift", swift_name(url), version))
    return items


def read_podfile_lock(path):
    items = []
    for line in path.read_text().splitlines():
        if line and not line.startswith(" ") and line != "PODS:":
            break
        match = re.match(r'^  - "?([^\s"(]+) \(([^)]+)\)"?:?$', line)
        if match:
            items.append(component("cocoapods", match.group(1), match.group(2)))
    return items


READERS = {
    "requirements.txt": read_requirements,
    "pyproject.toml": read_pyproject,
    "poetry.lock": read_python_lock,
    "uv.lock": read_python_lock,
    "package-lock.json": read_package_lock,
    "package.json": read_package_json,
    "Gemfile.lock": read_gemfile_lock,
    "go.mod": read_go_mod,
    "Cargo.lock": read_cargo_lock,
    "composer.lock": read_composer_lock,
    "Package.resolved": read_package_resolved,
    "Podfile.lock": read_podfile_lock,
}


def reader_for(name):
    if name in READERS:
        return READERS[name]
    if re.fullmatch(r"requirements[\w.-]*\.txt", name):
        return read_requirements
    return None


def manifests(folder):
    for root, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            reader = reader_for(name)
            if reader:
                yield Path(root) / name, reader


def scan(folder):
    folder = Path(folder)
    found = {}
    for path, reader in manifests(folder):
        rel = path.relative_to(folder).as_posix()
        try:
            items = reader(path)
        except (ValueError, KeyError, TypeError, AttributeError, tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
            print(f"Skipping {rel}: {e}", file=sys.stderr)
            continue
        for item in items:
            existing = found.setdefault(item["purl"], {**item, "bom-ref": item["purl"], "properties": []})
            source = {"name": "sbom:source", "value": rel}
            if source not in existing["properties"]:
                existing["properties"].append(source)
    return sorted(found.values(), key=lambda c: c["purl"])


def build_bom(folder, timestamp=None, serial=None):
    folder = Path(folder).resolve()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "sbom.py", "version": VERSION}]},
            "component": {"type": "application", "name": folder.name, "bom-ref": folder.name},
        },
        "components": scan(folder),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan a folder's dependency manifests and write a CycloneDX sbom.json.")
    parser.add_argument("folder", nargs="?", default=".", help="folder to scan (default: the current folder)")
    parser.add_argument("-o", "--output", help="where to write the SBOM (default: <folder>/sbom.json)")
    args = parser.parse_args(argv)

    folder = Path(args.folder)
    if not folder.is_dir():
        print(f"{folder} is not a folder", file=sys.stderr)
        return 2
    output = Path(args.output) if args.output else folder / "sbom.json"
    bom = build_bom(folder)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"Wrote {len(bom['components'])} components to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
