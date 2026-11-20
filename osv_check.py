import argparse
import json
import sys
import urllib.request
from pathlib import Path

VERSION = "1.1.0"
API = "https://api.osv.dev/v1"
BATCH_SIZE = 1000
SEVERITIES = ["CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW", "UNKNOWN"]
USER_AGENT = f"osv_check.py/{VERSION} (+https://github.com/SecOpsNews/script_sbom.py)"


def post_json(url, payload):
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def get_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def severity(vuln):
    if vuln.get("id", "").startswith("MAL-"):
        return "CRITICAL"
    level = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    if level in SEVERITIES:
        return level
    for affected in vuln.get("affected", []):
        level = str((affected.get("ecosystem_specific") or {}).get("severity", "")).upper()
        if level in SEVERITIES:
            return level
    return "UNKNOWN"


def fixed_versions(vuln, name):
    fixed = []
    for affected in vuln.get("affected", []):
        package = affected.get("package") or {}
        if package.get("name", "").lower() != name.lower():
            continue
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event and event["fixed"] not in fixed:
                    fixed.append(event["fixed"])
    return fixed


def summary(vuln):
    text = vuln.get("summary") or (vuln.get("details") or "").strip().split("\n", 1)[0]
    return text if len(text) <= 200 else text[:197].rsplit(" ", 1)[0] + "…"


def cve(vuln):
    ids = [vuln.get("id", "")] + list(vuln.get("aliases") or [])
    return next((i for i in ids if i.startswith("CVE-")), "")


def merge(vulns):
    kept = []
    for vuln in sorted(vulns, key=lambda v: (not v["id"].startswith("GHSA-"), v["id"])):
        names = {vuln["id"], *(vuln.get("aliases") or [])}
        if any(names & {k["id"], *(k.get("aliases") or [])} for k in kept):
            continue
        kept.append(vuln)
    return kept


def check_bom(bom):
    components = [c for c in bom.get("components", []) if c.get("purl")]
    checkable = [c for c in components if c.get("version")]
    unchecked = [c["purl"] for c in components if not c.get("version")]
    ids_per_purl = {}
    for start in range(0, len(checkable), BATCH_SIZE):
        batch = checkable[start:start + BATCH_SIZE]
        response = post_json(f"{API}/querybatch", {"queries": [{"package": {"purl": c["purl"]}} for c in batch]})
        for component, result in zip(batch, response.get("results", [])):
            ids_per_purl[component["purl"]] = [v["id"] for v in result.get("vulns") or []]

    cache = {}
    vulnerable = []
    for component in checkable:
        ids = ids_per_purl.get(component["purl"], [])
        for vuln_id in ids:
            if vuln_id not in cache:
                cache[vuln_id] = get_json(f"{API}/vulns/{vuln_id}")
        for vuln in merge([cache[i] for i in ids]):
            vulnerable.append({
                "package": component["name"],
                "version": component["version"],
                "purl": component["purl"],
                "id": vuln["id"],
                "cve": cve(vuln),
                "severity": severity(vuln),
                "summary": summary(vuln),
                "fixed": fixed_versions(vuln, component["purl"].split("@")[0].rsplit("/", 1)[-1]) or
                fixed_versions(vuln, component["name"]),
            })
    vulnerable.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["package"].lower(), f["id"]))
    return {"checked": len(checkable), "unchecked": unchecked, "vulnerable": vulnerable}


def _plural(n, word, plural=None):
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def report(findings):
    lines = ["# Vulnerability check", ""]
    vulnerable = findings["vulnerable"]
    checked = findings["checked"]
    if vulnerable:
        packages = len({f["purl"] for f in vulnerable})
        counts = [f"{sum(1 for f in vulnerable if f['severity'] == s)} {s.lower()}"
                  for s in SEVERITIES if any(f["severity"] == s for f in vulnerable)]
        lines.append(f"{_plural(len(vulnerable), 'known vulnerability', 'known vulnerabilities')} in "
                     f"{packages} of {_plural(checked, 'package')} checked ({', '.join(counts)}).")
    else:
        lines.append(f"No known vulnerabilities in {_plural(checked, 'package')} checked.")
    if findings["unchecked"]:
        listed = ", ".join(f"`{p}`" for p in findings["unchecked"][:20])
        more = f" and {len(findings['unchecked']) - 20} more" if len(findings["unchecked"]) > 20 else ""
        verb = "it has" if len(findings["unchecked"]) == 1 else "they have"
        lines += ["", f"{_plural(len(findings['unchecked']), 'package')} not checked, because {verb} no pinned "
                      f"version: {listed}{more}."]
    if vulnerable:
        lines += ["", "| Severity | Package | Version | Vulnerability | Fixed in | Summary |", "|---|---|---|---|---|---|"]
        for f in vulnerable:
            label = f["cve"] or f["id"]
            link = f"[{label}](https://osv.dev/vulnerability/{f['id']})"
            fixed = ", ".join(f["fixed"]) or "No fix yet"
            text = f["summary"].replace("|", "\\|")
            lines.append(f"| {f['severity'].title()} | {f['package']} | {f['version']} | {link} | {fixed} | {text} |")
    lines += ["", "Data from [OSV.dev](https://osv.dev)."]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check a CycloneDX sbom.json for known vulnerabilities with OSV.dev.")
    parser.add_argument("sbom", nargs="?", default="sbom.json", help="the SBOM to check (default: sbom.json)")
    parser.add_argument("-o", "--output", help="also write the Markdown report to this file")
    parser.add_argument("--json", help="also write the findings as JSON to this file")
    parser.add_argument("--no-fail", action="store_true", help="exit 0 even when vulnerabilities are found")
    args = parser.parse_args(argv)

    path = Path(args.sbom)
    if not path.is_file():
        print(f"{path} not found", file=sys.stderr)
        return 2
    try:
        bom = json.loads(path.read_text())
    except ValueError:
        bom = {}
    if bom.get("bomFormat") != "CycloneDX":
        print(f"{path} isn't a CycloneDX JSON SBOM", file=sys.stderr)
        return 2

    findings = check_bom(bom)
    text = report(findings)
    print(text)
    if args.output:
        Path(args.output).write_text(text)
    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2) + "\n")
    return 1 if findings["vulnerable"] and not args.no_fail else 0


if __name__ == "__main__":
    sys.exit(main())
