from __future__ import annotations

import pytest

from tests.support import make_decoy, make_finding, make_oracle
from vulnmirage.config import MatchingConfig
from vulnmirage.evaluation.matching import (
    _hungarian_max,
    finding_hits_location,
    location_similarity,
    match_instance,
)
from vulnmirage.models import CodeLocation


@pytest.fixture
def config() -> MatchingConfig:
    return MatchingConfig()


def _shifted(finding, delta: int):
    locations = [
        item.model_copy(update={"start_line": item.start_line + delta, "end_line": item.end_line + delta})
        for item in finding.locations
    ]
    entry = (
        finding.entry_point.model_copy(
            update={
                "start_line": finding.entry_point.start_line + delta,
                "end_line": finding.entry_point.end_line + delta,
            }
        )
        if finding.entry_point
        else None
    )
    critical = (
        finding.critical_operation.model_copy(
            update={
                "start_line": finding.critical_operation.start_line + delta,
                "end_line": finding.critical_operation.end_line + delta,
            }
        )
        if finding.critical_operation
        else None
    )
    trace = [
        item.model_copy(update={"start_line": item.start_line + delta, "end_line": item.end_line + delta})
        for item in finding.trace
    ]
    return finding.model_copy(
        update={
            "locations": locations,
            "entry_point": entry,
            "critical_operation": critical,
            "trace": trace,
        }
    )


def test_exact_match(config) -> None:
    outcome = match_instance([make_finding()], make_oracle(), config=config)
    assert outcome.matched_count == 1
    assert outcome.matches[0].score == pytest.approx(1.0)
    assert not outcome.unmatched_finding_ids
    assert not outcome.conflicts


def test_line_tolerance_allows_small_shift(config) -> None:
    outcome = match_instance([_shifted(make_finding(), 4)], make_oracle(), config=config)
    assert outcome.matched_count == 1
    record = outcome.matches[0]
    assert record.critical_operation_match == pytest.approx(0.9)
    assert record.matched


def test_large_shift_does_not_match(config) -> None:
    outcome = match_instance([_shifted(make_finding(), 10)], make_oracle(), config=config)
    assert outcome.matched_count == 0
    assert outcome.unmatched_finding_ids == ["F-1"]


def test_different_critical_file_never_matches(config) -> None:
    finding = make_finding()
    critical = CodeLocation(file="app/other.py", start_line=1, end_line=2)
    finding = finding.model_copy(update={"critical_operation": critical})
    outcome = match_instance([finding], make_oracle(), config=config)
    assert outcome.matched_count == 0


def test_strict_requires_matching_entry_file_but_relaxed_does_not(config) -> None:
    finding = make_finding().model_copy(update={"entry_point": None})
    strict = match_instance([finding], make_oracle(), config=config, profile="strict")
    relaxed = match_instance([finding], make_oracle(), config=config, profile="relaxed")
    assert strict.matched_count == 0
    assert relaxed.matched_count == 1


def test_one_finding_matches_at_most_one_path(config) -> None:
    import copy

    oracle = make_oracle()
    # Duplicate the vulnerability/path so there are two identical ground-truth paths.
    payload = oracle.model_dump(mode="json")
    second = copy.deepcopy(payload["vulnerabilities"][0])
    second["vulnerability_id"] = "VULN-2"
    second["paths"][0]["path_id"] = "PATH-2"
    payload["vulnerabilities"].append(second)
    from vulnmirage.models import CanonicalVulnerabilityOracle

    oracle = CanonicalVulnerabilityOracle.model_validate(payload)
    outcome = match_instance([make_finding()], oracle, config=config)
    assert outcome.matched_count == 1
    assert len(outcome.strict_assignment) == 1


def test_decoy_is_not_matched_to_real_vulnerability(config) -> None:
    finding = make_finding()
    decoy_location = CodeLocation(file="app/legacy_report.py", start_line=20, end_line=22)
    finding = finding.model_copy(
        update={
            "critical_operation": decoy_location,
            "locations": [decoy_location],
            "entry_point": CodeLocation(file="app/legacy_report.py", start_line=1, end_line=2),
            "trace": [],
        }
    )
    outcome = match_instance(
        [finding], make_oracle(), decoys=[make_decoy()], config=config
    )
    assert outcome.matched_count == 0
    assert outcome.matches[0].matched_decoy is True
    assert outcome.matches[0].decoy_id == "DECOY-1"
    assert "F-1" in outcome.decoy_finding_ids


def test_hungarian_max_assignment() -> None:
    weights = [
        [0.9, 0.1],
        [0.8, 0.7],
    ]
    assignment = _hungarian_max(weights)
    assert assignment == {0: 0, 1: 1}
    assignment = _hungarian_max([[0.1, 0.9], [0.8, 0.2]])
    assert assignment == {0: 1, 1: 0}


def test_location_similarity() -> None:
    left = CodeLocation(file="a.py", start_line=10, end_line=12)
    assert location_similarity(left, CodeLocation(file="a.py", start_line=11, end_line=11), 5) == 1.0
    assert location_similarity(left, CodeLocation(file="a.py", start_line=15, end_line=16), 5) == pytest.approx(0.9)
    assert location_similarity(left, CodeLocation(file="b.py", start_line=10, end_line=12), 5) == 0.0


def test_finding_hits_safe_location() -> None:
    finding = make_finding()
    assert finding_hits_location(
        finding, CodeLocation(file="app/storage.py", start_line=2, end_line=2), 5
    )
    assert not finding_hits_location(
        finding, CodeLocation(file="app/safe.py", start_line=1, end_line=2), 5
    )
