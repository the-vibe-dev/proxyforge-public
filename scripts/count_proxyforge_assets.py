#!/usr/bin/env python3
"""
Count ProxyForge repository assets for README badge updates.

Run from the ProxyForge repository root:

    python scripts/count_proxyforge_assets.py

The script intentionally counts files/patterns, not marketing claims.
"""
from __future__ import annotations
from pathlib import Path
import json
import fnmatch

ROOT = Path.cwd()

PATTERNS = {
    "skill_markdown_files": ["agent_skills/**/SKILL.md", "**/skills/**/SKILL.md", "**/*skill*.md"],
    "playbook_yaml_files": ["playbooks/**/*.yaml", "playbooks/**/*.yml", "**/*.playbook.yaml", "**/*.playbook.yml"],
    "theory_yaml_files": ["theories/**/*.yaml", "theories/**/*.yml", "**/*.theory.yaml", "**/*.theory.yml"],
    "bcheck_files": ["**/*.bcheck"],
    "extension_manifests": ["extensions/**/manifest.json", "extensions/**/manifest.yaml", "extensions/**/manifest.yml"],
    "automation_recipes": ["**/*automation*.json", "**/*automation*.yaml", "**/*automation*.yml", "**/*recipe*.json", "**/*recipe*.yaml", "**/*recipe*.yml"],
    "report_templates": ["reports/**/*template*", "templates/**/*report*", "**/*report-template*"],
}

IGNORE_PARTS = {".git", "node_modules", "dist", "build", "out", ".vite", "coverage", ".next"}

def should_ignore(path: Path) -> bool:
    return any(part in IGNORE_PARTS for part in path.parts)

def glob_many(patterns: list[str]) -> set[str]:
    results: set[str] = set()
    for pattern in patterns:
        for path in ROOT.glob(pattern):
            if path.is_file() and not should_ignore(path.relative_to(ROOT)):
                results.add(str(path.relative_to(ROOT)))
    return results

counts = {}
files = {}
for key, patterns in PATTERNS.items():
    matched = sorted(glob_many(patterns))
    counts[key] = len(matched)
    files[key] = matched

# Also count package scripts when package.json exists.
pkg = ROOT / "package.json"
if pkg.exists():
    import json as _json
    data = _json.loads(pkg.read_text(encoding="utf-8"))
    scripts = data.get("scripts", {})
    counts["package_scripts"] = len(scripts)
    counts["test_scripts"] = sum(1 for name in scripts if name.startswith("test"))
    files["package_scripts"] = sorted(scripts)

output = {"counts": counts, "files": files}
print(json.dumps(output, indent=2))
