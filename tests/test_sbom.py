import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("sbom", ROOT / "sbom.py")
sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sbom)


def write(base, rel, text):
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def purls(folder):
    return {c["purl"] for c in sbom.scan(folder)}


def test_requirements_txt(tmp_path):
    write(tmp_path, "requirements.txt", "\n".join([
        "# comment",
        "Requests==2.32.3",
        "my_pkg[extra]==1.0 ; python_version > '3.8'",
        "flask>=3.0",
        "-r other.txt",
        "-e .",
        "git+https://github.com/x/y.git",
        "",
    ]))
    assert purls(tmp_path) == {
        "pkg:pypi/requests@2.32.3",
        "pkg:pypi/my-pkg@1.0",
        "pkg:pypi/flask",
    }


def test_pyproject_dependencies(tmp_path):
    write(tmp_path, "pyproject.toml", '[project]\nname = "app"\ndependencies = ["httpx==0.27.0", "rich>=13"]\n')
    assert purls(tmp_path) == {"pkg:pypi/httpx@0.27.0", "pkg:pypi/rich"}


def test_poetry_and_uv_locks_win_over_pyproject(tmp_path):
    write(tmp_path, "a/pyproject.toml", '[project]\nname = "a"\ndependencies = ["httpx>=0.27"]\n')
    write(tmp_path, "a/poetry.lock", '[[package]]\nname = "httpx"\nversion = "0.27.2"\n')
    write(tmp_path, "b/pyproject.toml", '[project]\nname = "b"\ndependencies = ["rich"]\n')
    write(tmp_path, "b/uv.lock", "\n".join([
        "version = 1",
        "[[package]]",
        'name = "b"',
        'version = "0.1.0"',
        'source = { editable = "." }',
        "[[package]]",
        'name = "rich"',
        'version = "13.9.4"',
        'source = { registry = "https://pypi.org/simple" }',
        "",
    ]))
    assert purls(tmp_path) == {"pkg:pypi/httpx@0.27.2", "pkg:pypi/rich@13.9.4"}


def test_package_lock_v3(tmp_path):
    write(tmp_path, "package.json", json.dumps({"dependencies": {"left-pad": "^1.0.0"}}))
    write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/@types/node": {"version": "22.1.0", "dev": True},
            "node_modules/a/node_modules/b": {"version": "2.0.0"},
            "packages/local": {"version": "0.0.1"},
            "node_modules/linked": {"link": True},
        },
    }))
    assert purls(tmp_path) == {
        "pkg:npm/left-pad@1.3.0",
        "pkg:npm/%40types/node@22.1.0",
        "pkg:npm/b@2.0.0",
    }


def test_package_lock_v1(tmp_path):
    write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 1,
        "dependencies": {"a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}}},
    }))
    assert purls(tmp_path) == {"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"}


def test_package_json_without_lock(tmp_path):
    write(tmp_path, "package.json", json.dumps({
        "dependencies": {"express": "4.21.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }))
    assert purls(tmp_path) == {"pkg:npm/express@4.21.0", "pkg:npm/jest"}


def test_gemfile_lock(tmp_path):
    write(tmp_path, "Gemfile.lock", "\n".join([
        "GEM",
        "  remote: https://rubygems.org/",
        "  specs:",
        "    jekyll (4.3.4)",
        "      addressable (~> 2.4)",
        "    nokogiri (1.16.7-arm64-darwin)",
        "",
        "PLATFORMS",
        "  arm64-darwin",
        "",
    ]))
    assert purls(tmp_path) == {"pkg:gem/jekyll@4.3.4", "pkg:gem/nokogiri@1.16.7-arm64-darwin"}


def test_go_mod(tmp_path):
    write(tmp_path, "go.mod", "\n".join([
        "module example.com/app",
        "go 1.23",
        "require github.com/pkg/errors v0.9.1",
        "require (",
        "\tgolang.org/x/text v0.21.0 // indirect",
        ")",
        "",
    ]))
    assert purls(tmp_path) == {
        "pkg:golang/github.com/pkg/errors@v0.9.1",
        "pkg:golang/golang.org/x/text@v0.21.0",
    }


def test_cargo_lock_skips_workspace_members(tmp_path):
    write(tmp_path, "Cargo.lock", "\n".join([
        "version = 3",
        "[[package]]",
        'name = "app"',
        'version = "0.1.0"',
        "[[package]]",
        'name = "serde"',
        'version = "1.0.215"',
        'source = "registry+https://github.com/rust-lang/crates.io-index"',
        "",
    ]))
    assert purls(tmp_path) == {"pkg:cargo/serde@1.0.215"}


def test_composer_lock(tmp_path):
    write(tmp_path, "composer.lock", json.dumps({
        "packages": [{"name": "monolog/monolog", "version": "3.8.0"}],
        "packages-dev": [{"name": "phpunit/phpunit", "version": "11.4.0"}],
    }))
    assert purls(tmp_path) == {"pkg:composer/monolog/monolog@3.8.0", "pkg:composer/phpunit/phpunit@11.4.0"}


def test_swift_package_resolved_v2_and_v1(tmp_path):
    write(tmp_path, "App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved", json.dumps({
        "version": 2,
        "pins": [{"identity": "swift-collections", "location": "https://github.com/apple/swift-collections.git",
                  "state": {"version": "1.1.4"}}],
    }))
    write(tmp_path, "old/Package.resolved", json.dumps({
        "version": 1,
        "object": {"pins": [{"package": "Alamofire", "repositoryURL": "https://github.com/Alamofire/Alamofire",
                             "state": {"version": "5.9.1"}}]},
    }))
    assert purls(tmp_path) == {
        "pkg:swift/github.com/apple/swift-collections@1.1.4",
        "pkg:swift/github.com/Alamofire/Alamofire@5.9.1",
    }


def test_podfile_lock(tmp_path):
    write(tmp_path, "Podfile.lock", "\n".join([
        "PODS:",
        "  - Firebase/Core (11.5.0):",
        "    - FirebaseCore (= 11.5.0)",
        "  - FirebaseCore (11.5.0)",
        "",
        "DEPENDENCIES:",
        "  - Firebase/Core",
        "",
    ]))
    assert purls(tmp_path) == {"pkg:cocoapods/Firebase/Core@11.5.0", "pkg:cocoapods/FirebaseCore@11.5.0"}


def test_skips_vendor_and_environment_folders(tmp_path):
    write(tmp_path, "requirements.txt", "a==1\n")
    for skipped in ["node_modules/x", ".venv/lib", ".git/x", "venv", "Pods/x", "vendor/bundle"]:
        write(tmp_path, f"{skipped}/requirements.txt", "b==2\n")
    assert purls(tmp_path) == {"pkg:pypi/a@1"}


def test_same_package_in_two_places_is_listed_once_with_both_sources(tmp_path):
    write(tmp_path, "one/requirements.txt", "a==1\n")
    write(tmp_path, "two/requirements.txt", "a==1\n")
    components = sbom.scan(tmp_path)
    assert len(components) == 1
    sources = [p["value"] for p in components[0]["properties"] if p["name"] == "sbom:source"]
    assert sources == ["one/requirements.txt", "two/requirements.txt"]


def test_bad_manifest_is_reported_and_skipped(tmp_path, capsys):
    write(tmp_path, "package-lock.json", "{not json")
    write(tmp_path, "requirements.txt", "a==1\n")
    assert purls(tmp_path) == {"pkg:pypi/a@1"}
    assert "package-lock.json" in capsys.readouterr().err


def test_bom_is_cyclonedx(tmp_path):
    write(tmp_path, "requirements.txt", "b==2\na==1\n")
    bom = sbom.build_bom(tmp_path, timestamp="2026-11-20T00:00:00Z", serial="urn:uuid:test")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"] == "urn:uuid:test"
    assert bom["metadata"]["timestamp"] == "2026-11-20T00:00:00Z"
    assert bom["metadata"]["component"]["name"] == tmp_path.name
    assert [c["name"] for c in bom["components"]] == ["a", "b"]
    first = bom["components"][0]
    assert first["type"] == "library" and first["version"] == "1" and first["bom-ref"] == first["purl"]


def test_component_without_version_has_no_version_key(tmp_path):
    write(tmp_path, "requirements.txt", "flask>=3\n")
    component = sbom.scan(tmp_path)[0]
    assert "version" not in component


def test_cli_writes_file(tmp_path):
    write(tmp_path, "requirements.txt", "a==1\n")
    out = tmp_path / "out" / "sbom.json"
    assert sbom.main([str(tmp_path), "-o", str(out)]) == 0
    assert json.loads(out.read_text())["components"][0]["purl"] == "pkg:pypi/a@1"


def test_cli_does_not_scan_its_own_output(tmp_path):
    write(tmp_path, "requirements.txt", "a==1\n")
    assert sbom.main([str(tmp_path)]) == 0
    assert sbom.main([str(tmp_path)]) == 0
    assert len(json.loads((tmp_path / "sbom.json").read_text())["components"]) == 1


def test_cli_missing_folder(tmp_path, capsys):
    assert sbom.main([str(tmp_path / "nope")]) == 2
    assert "not a folder" in capsys.readouterr().err
