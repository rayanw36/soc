"""
C6 -- Claim provenance (Binary).

Spec: docs/controls_spec.md. Every reported claim must name an artifact
that produced it. Implemented as a process control over docs/claims.csv
(Task 5): every row's source_file must exist on disk; the check FAILs on
any row whose named file is missing.
"""
import csv
import os
from dataclasses import dataclass, field
from typing import List


@dataclass
class C6Result:
    verdict: str
    n_claims: int
    n_missing: int
    missing_rows: List[dict] = field(default_factory=list)
    reason: str = ""


def run(claims_csv_path: str, repo_root: str) -> C6Result:
    """
    claims_csv_path: path to docs/claims.csv (columns: section, claim,
        value, source_file, how_computed).
    repo_root: directory that source_file paths are relative to.
    """
    if not os.path.isfile(claims_csv_path):
        return C6Result("FAIL", 0, 0, [], reason=f"claims file not found: {claims_csv_path}")

    missing = []
    n = 0
    with open(claims_csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            n += 1
            src = (row.get("source_file") or "").strip()
            if not src:
                missing.append(row)
                continue
            # a row may name more than one file (semicolon-separated)
            names = [s.strip() for s in src.split(";") if s.strip()]
            if not names or not all(os.path.exists(os.path.join(repo_root, s)) for s in names):
                missing.append(row)

    verdict = "FAIL" if missing else "PASS"
    reason = (f"{len(missing)} of {n} claims name a missing or empty source_file"
              if missing else f"all {n} claims name an existing source_file")
    return C6Result(verdict, n, len(missing), missing, reason)
