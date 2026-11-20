import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("osv_check", ROOT / "osv_check.py")
osv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(osv)

VULNS = {
    "GHSA-x84v-xcm2-53pg": {
        "id": "GHSA-x84v-xcm2-53pg",
        "summary": "Insufficiently Protected Credentials in Requests",
        "aliases": ["CVE-2018-18074", "PYSEC-2018-28"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "requests", "ecosystem": "PyPI", "purl": "pkg:pypi/requests"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
    },
    "PYSEC-2018-28": {
        "id": "PYSEC-2018-28",
        "details": "The Requests package before 2.20.0 sends an HTTP Authorization header to an http URI.",
        "aliases": ["CVE-2018-18074", "GHSA-x84v-xcm2-53pg"],
        "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}],
    },
    "GHSA-crit-0000-0000": {
        "id": "GHSA-crit-0000-0000",
        "summary": "Remote code execution in left-pad",
        "aliases": [],
        "database_specific": {"severity": "CRITICAL"},
        "affected": [{"package": {"name": "left-pad", "ecosystem": "npm"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.3.1"}]}]}],
    },
    "MAL-2026-1": {
        "id": "MAL-2026-1",
        "summary": "Malicious code in tiny",
        "affected": [{"package": {"name": "tiny", "ecosystem": "npm"}, "ranges": []}],
    },
}


def bom(*components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": list(components)}


def comp(purl, name, version=None):
    c = {"type": "library", "name": name, "purl": purl}
    if version:
        c["version"] = version
    return c


class FakeOSV:
    def __init__(self, results):
        self.results = results
        self.batches = []
        self.fetched = []

    def post(self, url, payload):
        self.batches.append(payload)
        return {"results": [{"vulns": [{"id": i} for i in self.results.get(q["package"]["purl"], [])]}
                            for q in payload["queries"]]}

    def get(self, url):
        vuln_id = url.rsplit("/", 1)[1]
        self.fetched.append(vuln_id)
        return VULNS[vuln_id]


def run(components, results, monkeypatch, batch_size=None):
    fake = FakeOSV(results)
    monkeypatch.setattr(osv, "post_json", fake.post)
    monkeypatch.setattr(osv, "get_json", fake.get)
    if batch_size:
        monkeypatch.setattr(osv, "BATCH_SIZE", batch_size)
    return osv.check_bom(bom(*components)), fake


def test_finds_vulnerabilities_and_merges_aliases(monkeypatch):
    findings, fake = run(
        [comp("pkg:pypi/requests@2.19.0", "requests", "2.19.0")],
        {"pkg:pypi/requests@2.19.0": ["GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"]},
        monkeypatch,
    )
    assert len(findings["vulnerable"]) == 1
    f = findings["vulnerable"][0]
    assert f["package"] == "requests" and f["version"] == "2.19.0"
    assert f["id"] == "GHSA-x84v-xcm2-53pg"
    assert f["cve"] == "CVE-2018-18074"
    assert f["severity"] == "HIGH"
    assert f["fixed"] == ["2.20.0"]
    assert f["summary"] == "Insufficiently Protected Credentials in Requests"


def test_unversioned_components_are_not_checked(monkeypatch):
    findings, fake = run([comp("pkg:pypi/flask", "flask")], {}, monkeypatch)
    assert findings["unchecked"] == ["pkg:pypi/flask"]
    assert fake.batches == []


def test_queries_in_batches(monkeypatch):
    components = [comp(f"pkg:npm/p{i}@1.0.0", f"p{i}", "1.0.0") for i in range(5)]
    findings, fake = run(components, {}, monkeypatch, batch_size=2)
    assert [len(b["queries"]) for b in fake.batches] == [2, 2, 1]
    assert findings["checked"] == 5 and findings["vulnerable"] == []


def test_each_vulnerability_is_fetched_once(monkeypatch):
    findings, fake = run(
        [comp("pkg:pypi/requests@2.19.0", "requests", "2.19.0"), comp("pkg:pypi/requests@2.18.0", "requests", "2.18.0")],
        {"pkg:pypi/requests@2.19.0": ["GHSA-x84v-xcm2-53pg"], "pkg:pypi/requests@2.18.0": ["GHSA-x84v-xcm2-53pg"]},
        monkeypatch,
    )
    assert fake.fetched == ["GHSA-x84v-xcm2-53pg"]
    assert len(findings["vulnerable"]) == 2


def test_summary_falls_back_to_details_and_unknown_severity(monkeypatch):
    findings, _ = run(
        [comp("pkg:pypi/requests@2.19.0", "requests", "2.19.0")],
        {"pkg:pypi/requests@2.19.0": ["PYSEC-2018-28"]},
        monkeypatch,
    )
    f = findings["vulnerable"][0]
    assert f["severity"] == "UNKNOWN"
    assert f["summary"].startswith("The Requests package before 2.20.0")


def test_malicious_package_is_critical(monkeypatch):
    findings, _ = run([comp("pkg:npm/tiny@1.0.0", "tiny", "1.0.0")], {"pkg:npm/tiny@1.0.0": ["MAL-2026-1"]}, monkeypatch)
    assert findings["vulnerable"][0]["severity"] == "CRITICAL"
    assert findings["vulnerable"][0]["fixed"] == []


def test_report_is_sorted_by_severity(monkeypatch):
    findings, _ = run(
        [comp("pkg:pypi/requests@2.19.0", "requests", "2.19.0"), comp("pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0"),
         comp("pkg:pypi/flask", "flask")],
        {"pkg:pypi/requests@2.19.0": ["GHSA-x84v-xcm2-53pg"], "pkg:npm/left-pad@1.3.0": ["GHSA-crit-0000-0000"]},
        monkeypatch,
    )
    text = osv.report(findings)
    assert text.splitlines()[0] == "# Vulnerability check"
    assert "2 known vulnerabilities in 2 of 2 packages checked (1 critical, 1 high)." in text
    assert "1 package not checked, because it has no pinned version: `pkg:pypi/flask`." in text
    assert text.index("left-pad") < text.index("requests")
    assert "[CVE-2018-18074](https://osv.dev/vulnerability/GHSA-x84v-xcm2-53pg)" in text


def test_clean_report(monkeypatch):
    findings, _ = run([comp("pkg:npm/a@1.0.0", "a", "1.0.0")], {}, monkeypatch)
    assert "No known vulnerabilities in 1 package checked." in osv.report(findings)


def test_cli_exit_codes_and_output(tmp_path, monkeypatch):
    sbom_path = tmp_path / "sbom.json"
    sbom_path.write_text(json.dumps(bom(comp("pkg:npm/left-pad@1.3.0", "left-pad", "1.3.0"))))
    fake = FakeOSV({"pkg:npm/left-pad@1.3.0": ["GHSA-crit-0000-0000"]})
    monkeypatch.setattr(osv, "post_json", fake.post)
    monkeypatch.setattr(osv, "get_json", fake.get)
    out = tmp_path / "report.md"
    assert osv.main([str(sbom_path), "-o", str(out)]) == 1
    assert "left-pad" in out.read_text()
    assert osv.main([str(sbom_path), "--no-fail"]) == 0
    json_out = tmp_path / "findings.json"
    osv.main([str(sbom_path), "--no-fail", "--json", str(json_out)])
    assert json.loads(json_out.read_text())["vulnerable"][0]["id"] == "GHSA-crit-0000-0000"


def test_cli_rejects_a_file_that_is_not_cyclonedx(tmp_path, capsys):
    path = tmp_path / "x.json"
    path.write_text("{}")
    assert osv.main([str(path)]) == 2
    assert "CycloneDX" in capsys.readouterr().err


@pytest.mark.parametrize("missing", ["nope.json"])
def test_cli_missing_file(tmp_path, capsys, missing):
    assert osv.main([str(tmp_path / missing)]) == 2
    assert "not found" in capsys.readouterr().err
