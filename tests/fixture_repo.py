"""Create a small, deterministic local git repository for integration tests.

The fixture intentionally contains:

* one real SQL-injection vulnerability with two entry points;
* a fix commit;
* an executable PoC that succeeds on the vulnerable commit;
* a regression test;
* a safe function/decoy target.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulnmirage.repository.git import run_git

_DATES = {
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+0000",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+0000",
    "GIT_AUTHOR_NAME": "VulnMirage Fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.com",
    "GIT_COMMITTER_NAME": "VulnMirage Fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.com",
}

_FILES: dict[str, str] = {
    "README.md": """# Fixture project

A tiny web application used to test the VulnMirage pipeline.

## Usage

The application exposes two request handlers that both reach the shared query
helper in `app/storage.py`.
""",
    "SECURITY.md": """# Security policy

Please report suspected vulnerabilities privately.

The project runs its unit tests before release.
""",
    "docs/architecture.md": """# Architecture

```
HTTP handler -> request dispatcher -> storage query helper
```

Both `/search` and `/report` use the shared dispatcher in `app/main.py`.
""",
    "app/__init__.py": '"""Fixture application package."""\n',
    "app/storage.py": '''"""Storage helpers."""

import sqlite3


def execute_query(conn: sqlite3.Connection, user_input: str):
    """Run a query built from a request handler value."""
    query = "SELECT id, name FROM users WHERE name = '" + user_input + "'"
    return conn.execute(query).fetchall()
''',
    "app/main.py": '''"""Request dispatcher."""

import sqlite3

from .storage import execute_query

CONN = sqlite3.connect(":memory:")
CONN.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
CONN.execute("INSERT INTO users (name) VALUES ('alice'), ('bob'), ('carol')")
CONN.commit()


def handle(value: str):
    """Dispatch a value to the storage helper."""
    return execute_query(CONN, value)
''',
    "app/http.py": '''"""HTTP entry points."""

from .main import handle


def search(request):
    """Search users by a query parameter."""
    return handle(request.get("q", ""))
''',
    "app/report.py": '''"""Report entry points."""

from .main import handle


def build_report(request):
    """Build a report from a request identifier."""
    return handle(request.get("id", ""))
''',
    "app/safe.py": '''"""Safe helpers used as a false-positive target."""

import html


def render(value: str) -> str:
    """Escape user input for HTML output."""
    return html.escape(value, quote=True)
''',
    "app/parameters.py": '''"""Parameterized lookups that are provably safe from SQL injection."""

import sqlite3

ALLOWED_COLUMNS = {"name"}


def lookup_user(conn: sqlite3.Connection, value: str):
    """Look up one user by an exact, parameter-bound name."""
    column = "name"
    if column not in ALLOWED_COLUMNS:
        raise ValueError("unsupported column")
    query = "SELECT id, name FROM users WHERE " + column + " = ?"
    return conn.execute(query, (value,)).fetchall()
''',
    "poc/poc.py": '''"""Executable proof of concept for the SQL injection.

Exit code 0 means the vulnerable behaviour was observed; exit code 1 means the
injection was blocked (the patched behaviour).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.storage import execute_query  # noqa: E402
import sqlite3  # noqa: E402


def main() -> int:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO users (name) VALUES ('alice'), ('bob'), ('carol')")
    conn.commit()
    rows = execute_query(conn, "x' OR 1=1 --")
    if len(rows) == 3:
        print("VULNERABLE: injection returned all rows")
        return 0
    print(f"NOT VULNERABLE: injection returned {len(rows)} rows")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
''',
    "tests/test_app.py": '''"""Regression tests for safe behaviour."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.safe import render  # noqa: E402


class SafeRenderTests(unittest.TestCase):
    def test_escapes_script(self) -> None:
        self.assertEqual(render("<script>"), "&lt;script&gt;")

    def test_escapes_quotes(self) -> None:
        self.assertIn("&quot;", render('a"b'))


if __name__ == "__main__":
    unittest.main()
''',
}

_FIXED_STORAGE = '''"""Storage helpers."""

import sqlite3


def execute_query(conn: sqlite3.Connection, user_input: str):
    """Run a lookup that treats request data as a literal value."""
    return conn.execute(
        "SELECT id, name FROM users WHERE name = ?", (user_input,)
    ).fetchall()
'''

#: Executable proof that the declared safe target cannot be injected.
_SAFE_TARGET_SCRIPT = '''
import sqlite3
import sys

from app.parameters import lookup_user

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
conn.execute("INSERT INTO users (name) VALUES ('alice'), ('bob')")
conn.commit()
for payload in ["x' OR 1=1 --", "'; DROP TABLE users; --"]:
    rows = lookup_user(conn, payload)
    if rows:
        print(f"injection payload returned rows: {payload!r}")
        sys.exit(1)
rows = lookup_user(conn, "alice")
if len(rows) != 1:
    print(f"safe lookup returned {len(rows)} rows")
    sys.exit(2)
print("safe target verified")
sys.exit(0)
'''


@dataclass(frozen=True)
class FixtureRepo:
    path: Path
    vulnerable_commit: str
    fixed_commit: str
    repo_url: str
    reports_path: Path
    entries_path: Path
    entry_locations: dict[str, dict[str, Any]]

    @property
    def safe_file(self) -> str:
        return "app/safe.py"


def _find_line(path: Path, needle: str) -> int:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if needle in line:
            return number
    raise AssertionError(f"needle not found: {needle}")


def _git(repo: Path, *args: str) -> str:
    proc = run_git(list(args), cwd=repo, timeout=60, extra_env=_DATES)
    return proc.stdout.strip()


def create_fixture_repo(base: Path) -> FixtureRepo:
    repo = Path(base) / "fixture_repo"
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, "init")
    _git(repo, "checkout", "-b", "main")
    for relative, content in _FILES.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "initial vulnerable application")
    vulnerable = _git(repo, "rev-parse", "HEAD")

    (repo / "app" / "storage.py").write_text(_FIXED_STORAGE, encoding="utf-8", newline="\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "use a parameterized query")
    fixed = _git(repo, "rev-parse", "HEAD")

    storage = repo / "app" / "storage.py"
    # The fixed version no longer contains this line; use the vulnerable content
    # from the commit history for stable line numbers.
    original_storage = subprocess.run(
        ["git", "show", f"{vulnerable}:app/storage.py"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    original_lines = original_storage.splitlines()
    sql_line = next(
        index
        for index, line in enumerate(original_lines, start=1)
        if "conn.execute(query)" in line
    )
    http_line = _line_in_commit(repo, vulnerable, "app/http.py", "def search")
    report_line = _line_in_commit(repo, vulnerable, "app/report.py", "def build_report")
    main_line = _line_in_commit(repo, vulnerable, "app/main.py", "def handle")

    entry_locations = {
        "E1": {
            "file": "app/http.py",
            "line": f"{http_line}-{http_line + 1}",
            "ep": {"file": "app/http.py", "line": f"{http_line}-{http_line + 1}"},
            "co": {"file": "app/storage.py", "line": f"{sql_line}-{sql_line}"},
            "trace": [{"file": "app/main.py", "line": f"{main_line}-{main_line + 1}"}],
        },
        "E2": {
            "file": "app/report.py",
            "line": f"{report_line}-{report_line + 1}",
            "ep": {"file": "app/report.py", "line": f"{report_line}-{report_line + 1}"},
            "co": {"file": "app/storage.py", "line": f"{sql_line}-{sql_line}"},
            "trace": [{"file": "app/main.py", "line": f"{main_line}-{main_line + 1}"}],
        },
    }

    repo_url = repo.resolve().as_uri()
    report = {
        "report_id": "R-FIXTURE-1",
        "repo_url": repo_url,
        "commit": vulnerable,
        "fixed_commit": fixed,
        "title": "SQL injection in the shared query helper",
        "summary": "Request data reaches a raw SQL query, allowing filter bypass.",
        "cve_id": "CVE-2026-99999",
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "published": "2026-01-02",
        "url": "https://example.invalid/advisories/1",
        "severity": {
            "scheme": "cvss_v3.1",
            "level": "high",
            "cvss_score": 8.1,
            "rationale": "Network reachable, unauthenticated request parameter",
            "assumptions": ["the HTTP service is internet-facing"],
            "source": {"kind": "vendor", "reference": "fixture advisory"},
            "validation_status": "adjudicated",
            "confidence": 0.9,
        },
        "cwe": ["CWE-89"],
        "verify": 1,
        "license": "MIT",
        "safe_targets": [
            {
                "safe_target_id": "SAFE-PARAMETERIZED-LOOKUP",
                "file": "app/parameters.py",
                "line": "1-13",
                "cwe": "CWE-89",
                "vulnerability_type": "SQL injection",
                "safety_claim": (
                    "lookup_user binds the request value as a SQL parameter and "
                    "never concatenates it into the query."
                ),
                "proof_method": "human_annotated",
                "source": "human_annotation",
                "source_reference": "fixture security review",
                "validator_commands": [
                    {
                        "name": "parameterized-lookup-safety",
                        "argv": ["python", "-c", _SAFE_TARGET_SCRIPT],
                    }
                ],
            },
            {
                # This entry deliberately declares an XSS-safe target for a
                # CWE-89 oracle; the resolver must reject it, not silently use it.
                "safe_target_id": "SAFE-XSS-RENDER",
                "file": "app/safe.py",
                "line": "1-8",
                "cwe": "CWE-79",
                "vulnerability_type": "cross-site scripting",
                "safety_claim": "render escapes HTML metacharacters.",
                "proof_method": "human_annotated",
                "validator_commands": [
                    {
                        "name": "xss-render-safety",
                        "argv": ["python", "-c", "raise SystemExit(0)"],
                    }
                ],
            },
        ],
    }
    entries = []
    for entry_id, loc in entry_locations.items():
        entries.append(
            {
                "entry_id": entry_id,
                "report_id": "R-FIXTURE-1",
                "repo_url": repo_url,
                "commit": vulnerable,
                "file": loc["file"],
                "line": loc["line"],
                "function": "search" if entry_id == "E1" else "build_report",
                "entry_point": loc["ep"],
                "trace": loc["trace"],
                "critical_operation": loc["co"],
                "cwe": ["CWE-89"],
                "vulnerability_type": "SQL injection",
                "verify": 1,
                "poc_commands": [
                    {"name": "sql-injection-poc", "argv": ["python", "poc/poc.py"]}
                ],
                "regression_commands": [
                    {"name": "unit-tests", "argv": ["python", "tests/test_app.py"]}
                ],
            }
        )

    ingest_dir = Path(base) / "ingest"
    ingest_dir.mkdir(parents=True, exist_ok=True)
    reports_path = ingest_dir / "reports.jsonl"
    entries_path = ingest_dir / "entries.jsonl"
    reports_path.write_text(json.dumps(report) + "\n", encoding="utf-8", newline="\n")
    entries_path.write_text(
        "\n".join(json.dumps(entry) for entry in entries) + "\n", encoding="utf-8", newline="\n"
    )
    return FixtureRepo(
        path=repo,
        vulnerable_commit=vulnerable,
        fixed_commit=fixed,
        repo_url=repo_url,
        reports_path=reports_path,
        entries_path=entries_path,
        entry_locations=entry_locations,
    )


def _line_in_commit(repo: Path, commit: str, relative: str, needle: str) -> int:
    content = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for number, line in enumerate(content.splitlines(), start=1):
        if needle in line:
            return number
    raise AssertionError(f"{needle} not found in {relative}")


