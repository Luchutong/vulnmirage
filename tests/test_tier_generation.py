"""Acceptance tests for the tier-based generation subsystem (design §3-§14).

Each test pins one claim the design makes, and the claims are deliberately the
falsifiable ones:

* T0 still renders exactly what the pre-package code rendered (golden parity);
* T0/T1 cannot receive oracle material, and their manifests say so;
* the T2 view is an allowlist sanitizer, and a CVE-only target is ineligible;
* validation blocks a candidate instead of selecting a weaker one;
* selection is reproducible and recorded before any run;
* remap keeps a target inside its function when a payload shifts the file;
* the pipeline freezes generation before building trees, and aggregation counts
  attrition instead of hiding it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

from test_campaign_revision import (
    ANSWER_SCRIPT,
    _write_fixture_repo,
    make_dataset,
    write_config,
)

from vulnmirage.campaign.executor import CommandExecutor
from vulnmirage.campaign.plan import build_plan
from vulnmirage.campaign.pipeline import CampaignRunner
from vulnmirage.campaign.task_prompt import target_answer_tokens
from vulnmirage.campaign.variants import build_variant
from vulnmirage.config import VariantSpecConfig, load_config, with_variant_set
from vulnmirage.errors import CampaignError, GenerationError
from vulnmirage.ingest.dataset_core import load_dataset_core
from vulnmirage.hashing import sha256_file
from vulnmirage.payloadgen import (
    CandidatePayload,
    GenerationRequest,
    PlacementHint,
    PublicTaskView,
    TierBudget,
    build_context,
    build_oracle_attack_view,
    build_repository_index,
    generate_manifest,
    load_payload_catalog,
    realize_payload,
    remap_targets,
    selected_candidate,
    validate_candidate,
)
from vulnmirage.payloadgen.oracle_view import assert_view_is_clean
from vulnmirage.payloadgen.render import resolve_template_path
from vulnmirage.schemas import schema_index
from vulnmirage.verifier.targets import PrivateTarget, TargetSet

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG = PROJECT_ROOT / "PayloadGen" / "registry.yaml"


# --------------------------------------------------------------------------- fixtures
def _dataset(tmp_path: Path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    dataset = make_dataset(tmp_path / "dataset", repo, "a" * 40)
    core = load_dataset_core(dataset, strict=True)
    task_id = core.task_ids()[0]
    return repo, dataset, core, task_id


def _private_target() -> PrivateTarget:
    return PrivateTarget(
        target_id="tgt_fixture_0001",
        file="app/handler.py",
        function="lookup",
        line_start=3,
        line_end=5,
        cwe_ids=["CWE-89"],
        severity_level="high",
    )


def _method(payload_id: str = "M2-FEP__S-COMMENT-Z-TARGET__I1__R01"):
    return load_payload_catalog(CATALOG).by_id()[payload_id]


def _templates(method) -> dict[str, str]:
    templates: dict[str, str] = {}
    for tier in ("T0", "T1", "T2"):
        path = resolve_template_path(CATALOG, method.template_for(tier))
        templates[tier] = path.read_text(encoding="utf-8")
    templates.setdefault("T0", templates["T2"])
    return templates


def _request(
    *,
    repo: Path,
    tier: str,
    index=None,
    oracle_view=None,
    hint=None,
    budget: int = 3,
    templates=None,
    tokens=None,
):
    method = _method()
    return GenerationRequest(
        task_id="task_fixture_0001",
        snapshot_id="snap_fixture_0001",
        variant_id=f"A2-{tier}",
        condition_id=f"A2-{tier}",
        method_id=method.method_family,
        method_family=method.method_family,
        tier=tier,
        goal=method.objective,
        seed=0,
        carrier=method.carrier,
        placement=method.placement,
        output_path=method.output_path,
        task=PublicTaskView(task_id="task_fixture_0001", primary_language="Python"),
        templates=templates or _templates(method),
        template_source=str(CATALOG),
        budget=TierBudget(candidates=budget),
        limits=method.placement_limits,
        validation=method.validation,
        index=index,
        oracle_view=oracle_view,
        placement_hint=hint,
        forbidden_tokens=list(tokens or []),
        clean_tree_sha256="clean-tree-digest",
        input_hashes={"catalog": "hash"},
        repo_root=repo,
    )


# ------------------------------------------------------------------------- T0 parity
def test_every_declared_implemented_method_tier_generates_a_selectable_candidate(tmp_path):
    """Registry capability claims are executable contracts, not documentation."""
    repo, _dataset_root, core, task_id = _dataset(tmp_path)
    index = build_repository_index(repo, tree_sha256="clean-tree-digest")
    private = _private_target()
    target = core.targets(task_id)[0]
    tokens = target_answer_tokens(core, task_id)
    view, reason = build_oracle_attack_view(
        target, private_target=private, forbidden_tokens=tokens
    )
    assert view is not None, reason

    catalog = load_payload_catalog(CATALOG)
    checked: set[tuple[str, str]] = set()
    for method in catalog.methods:
        if method.reproduction_status != "implemented_adaptation":
            continue
        templates = _templates(method)
        for tier in method.supported_tiers:
            request = GenerationRequest(
                task_id=task_id,
                snapshot_id="snap_fixture_0001",
                variant_id=f"{method.method_id or method.method_family}-{tier}",
                condition_id=f"{method.method_id or method.method_family}-{tier}",
                method_id=method.method_id or method.method_family,
                method_family=method.method_family,
                taxonomy_version="vm-atk-1.0",
                threat_model_id="TM-REPOSITORY-CONTENT-01",
                realization_id=method.realization_id,
                tier=tier,
                goal=method.objective,
                primary_mechanism=method.primary_mechanism,
                surface=method.surface.model_dump(mode="json"),
                intensity=method.intensity,
                dose=method.dose.model_dump(mode="json"),
                carrier=method.carrier,
                placement=method.placement,
                output_path=method.output_path,
                task=PublicTaskView(task_id=task_id, primary_language="Python"),
                templates=templates,
                template_source=str(CATALOG),
                budget=TierBudget(
                    candidates=3,
                    max_files_changed=method.placement_limits.max_files_changed,
                    max_inserted_lines=method.placement_limits.max_inserted_lines,
                    max_payload_chars=method.placement_limits.max_payload_chars,
                ),
                limits=method.placement_limits,
                validation=method.validation,
                index=index if tier in {"T1", "T2"} else None,
                oracle_view=view if tier == "T2" else None,
                placement_hint=(
                    PlacementHint(
                        target_file=private.file,
                        target_function=private.function,
                        basis="legacy_target_anchor",
                    )
                    if tier == "T0" and method.placement == "target_file_footer"
                    else None
                ),
                forbidden_tokens=tokens,
                clean_tree_sha256="clean-tree-digest",
                repo_root=repo,
            )
            manifest = generate_manifest(request, method=method)
            candidate = selected_candidate(manifest)
            validation = manifest.validation_for(candidate.candidate_id)
            assert validation is not None and validation.selectable, (
                method.payload_id,
                tier,
                validation,
            )
            assert manifest.dose == method.dose.model_dump(mode="json")
            if (
                method.method_id
                in {
                    "M2-FALSE-PRIOR-RESOLUTION",
                    "M2-FALSE-EXPLOITABILITY-PREMISE",
                    "M2-FABRICATED-ANALYSIS-RESULT",
                }
                and tier == "T2"
            ):
                semantics_used = (
                    "oracle_view.local_semantics" in candidate.context_fields_used
                )
                assert semantics_used is (method.intensity in {"I2", "I3", "I4"})
            checked.add((method.payload_id, tier))

    expected = sum(
        len(method.supported_tiers)
        for method in catalog.methods
        if method.reproduction_status == "implemented_adaptation"
    )
    assert len(checked) == expected


def test_t0_generation_matches_the_preexisting_renderer_byte_for_byte(tmp_path):
    repo, _dataset_root, core, task_id = _dataset(tmp_path)
    tokens = target_answer_tokens(core, task_id)
    private = _private_target()
    spec = VariantSpecConfig(
        variant_id="A2-T0",
        kind="attack",
        generator_tier="T0",
        realization_id="M2-FEP__S-COMMENT-Z-TARGET__I1__R01",
    )
    legacy = realize_payload(catalog_path=CATALOG, spec=spec, targets=[private])

    manifest = generate_manifest(
        _request(
            repo=repo,
            tier="T0",
            hint=PlacementHint(
                target_file="app/handler.py",
                target_function="lookup",
                comment_prefix="#",
                basis="legacy_target_anchor",
            ),
            budget=1,
            tokens=tokens,
        ),
        method=_method(),
    )
    selected = selected_candidate(manifest)
    assert selected.rendered_text == legacy.spec.edits[0].text
    assert selected.target_file == "app/handler.py"
    assert selected.edit_op == "append"
    validation = manifest.validation_for(selected.candidate_id)
    assert validation is not None and validation.selectable


def test_t0_records_a_legacy_placement_basis_and_no_oracle_digest(tmp_path):
    repo, _dataset_root, core, task_id = _dataset(tmp_path)
    manifest = generate_manifest(
        _request(repo=repo, tier="T0", hint=PlacementHint(
            target_file="app/handler.py", target_function="lookup", comment_prefix="#",
            basis="legacy_target_anchor",
        ), budget=1, tokens=target_answer_tokens(core, task_id)),
        method=_method(),
    )
    selected = selected_candidate(manifest)
    assert selected.placement_basis == "legacy_target_anchor"
    assert selected.provenance["oracle_view_sha256"] == ""
    assert selected.provenance["index_sha256"] == ""
    assert manifest.index_sha256 is None
    assert manifest.oracle_view_sha256 is None


# ------------------------------------------------------------------ repository index
def test_repository_index_is_deterministic_and_role_aware(tmp_path):
    repo, _dataset_root, _core, _task = _dataset(tmp_path)
    generated = repo / "src" / "upb-generated"
    generated.mkdir(parents=True)
    (generated / "message.upb.h").write_text("void generated_call();\n", encoding="utf-8")
    first = build_repository_index(repo)
    second = build_repository_index(repo)
    assert first.index_sha256 == second.index_sha256
    assert first.digest() == second.digest()
    roles = {item.path: item.role for item in first.files}
    assert roles["app/handler.py"] == "source"
    assert roles["tests/test_handler.py"] == "test"
    assert roles["README.md"] == "docs"
    assert roles["src/upb-generated/message.upb.h"] == "generated"
    assert first.comment_styles["python"] == "#"
    names = {item.name for item in first.symbols if item.path == "app/handler.py"}
    assert {"lookup", "unrelated"} <= names
    assert first.files[0].parse_status in {"ast", "text_only", "not_parsed"}


# --------------------------------------------------------------------- oracle view
def test_oracle_view_strips_identity_fix_and_excerpt(tmp_path):
    _repo, _dataset_root, core, task_id = _dataset(tmp_path)
    record = core.targets(task_id)[0]
    view, reason = build_oracle_attack_view(
        record, private_target=_private_target(), forbidden_tokens=["tgt_fixture_0001"]
    )
    assert view is not None, reason
    serialized = json.dumps(view.model_dump(mode="json"))
    for forbidden in (
        "CVE-2024-99999",
        "CWE-89",
        "SQL injection",
        "octo/fixture",
        "a" * 40,
        "SELECT * FROM t",
        "tgt_fixture_0001",
    ):
        assert forbidden not in serialized
    assert view.locations[0].file == "app/handler.py"
    assert view.local_semantics.dangerous_effect
    assert view.local_semantics.required_preconditions
    assert_view_is_clean(view, ["tgt_fixture_0001"])


def test_a_target_with_only_an_advisory_label_is_ineligible_for_t2(tmp_path):
    _repo, _dataset_root, core, task_id = _dataset(tmp_path)
    record = core.targets(task_id)[0]
    stripped = record.model_copy(update={"prerequisites": [], "critical_operation": {}, "entry_point": {}})
    view, reason = build_oracle_attack_view(stripped, private_target=_private_target())
    assert view is None
    assert reason.startswith("ineligible_oracle_view")


# ------------------------------------------------------------- tier firewalls (T1)
def test_t1_generation_uses_the_index_and_never_the_oracle(tmp_path):
    repo, _dataset_root, core, task_id = _dataset(tmp_path)
    index = build_repository_index(repo)
    manifest = generate_manifest(
        _request(repo=repo, tier="T1", index=index, tokens=target_answer_tokens(core, task_id)),
        method=_method(),
    )
    assert manifest.index_sha256 == index.index_sha256
    assert manifest.oracle_view_sha256 is None
    for candidate in manifest.candidates:
        assert candidate.placement_basis == "repository_index"
        assert "index.symbols" in candidate.context_fields_used
        assert candidate.provenance["oracle_view_sha256"] == ""
        assert candidate.target_file == "app/handler.py"


def test_t1_context_refuses_an_oracle_view(tmp_path):
    repo, _dataset_root, core, task_id = _dataset(tmp_path)
    view, _reason = build_oracle_attack_view(core.targets(task_id)[0], private_target=_private_target())
    assert view is not None
    request = _request(repo=repo, tier="T1", index=build_repository_index(repo), oracle_view=view)
    with pytest.raises(GenerationError):
        build_context(request)


def test_repository_adaptive_generator_does_not_import_the_oracle_view():
    module = PROJECT_ROOT / "src" / "vulnmirage" / "payloadgen" / "generators" / "repository_adaptive.py"
    source = module.read_text(encoding="utf-8")
    assert "oracle_view" not in source
    static_module = PROJECT_ROOT / "src" / "vulnmirage" / "payloadgen" / "generators" / "static.py"
    assert "oracle_view" not in static_module.read_text(encoding="utf-8")


# ------------------------------------------------------------- tier behaviour (T2)
def test_t2_generation_places_at_the_oracle_location_without_leaking_it(tmp_path):
    repo, _dataset_root, core, task_id = _dataset(tmp_path)
    tokens = target_answer_tokens(core, task_id)
    view, _reason = build_oracle_attack_view(
        core.targets(task_id)[0], private_target=_private_target(), forbidden_tokens=tokens
    )
    assert view is not None
    manifest = generate_manifest(
        _request(
            repo=repo,
            tier="T2",
            index=build_repository_index(repo),
            oracle_view=view,
            tokens=tokens,
        ),
        method=_method(),
    )
    assert manifest.oracle_view_sha256 == view.source_sha256
    for candidate in manifest.candidates:
        assert candidate.target_file == "app/handler.py"
        assert candidate.placement_basis == "oracle_view"
        assert "oracle_view.locations" in candidate.context_fields_used
        assert "oracle_view.local_semantics" not in candidate.context_fields_used
        for forbidden in ("CVE-2024-99999", "CWE-89", "SELECT * FROM t"):
            assert forbidden not in candidate.rendered_text
    validation = manifest.validation_for(manifest.selection.selected_id)
    assert validation is not None and validation.selectable


# ------------------------------------------------------------------- validation gate
def test_a_candidate_that_leaks_an_answer_is_not_selectable(tmp_path):
    repo, _dataset_root, _core, _task = _dataset(tmp_path)
    poisoned = _templates(_method())
    poisoned["T0"] = "# see CVE-2024-99999 for details\n"
    request = _request(
        repo=repo,
        tier="T0",
        hint=PlacementHint(target_file="app/handler.py", target_function="lookup", basis="legacy_target_anchor"),
        budget=1,
        templates=poisoned,
        tokens=["CVE-2024-99999"],
    )
    with pytest.raises(GenerationError) as excinfo:
        generate_manifest(request, method=_method())
    assert "required validator" in excinfo.value.message


def test_structural_validator_refuses_an_escaping_path_and_a_bloated_payload(tmp_path):
    repo, _dataset_root, _core, _task = _dataset(tmp_path)
    context = build_context(
        _request(
            repo=repo,
            tier="T0",
            hint=PlacementHint(target_file="app/handler.py", target_function="lookup", basis="legacy_target_anchor"),
            budget=1,
        )
    )
    escaping = CandidatePayload(
        candidate_id="CAND-ESCAPE",
        variant_id="A2-T0",
        method_id="todo_false_safety",
        tier="T0",
        generator="test",
        carrier="comment",
        target_file="../outside.py",
        edit_op="create",
        rendered_text="# hi\n",
    ).finalized()
    validation = validate_candidate(escaping, context=context, repo_root=repo, forbidden_tokens=[])
    assert not validation.selectable
    assert any(item.validator == "structural" for item in validation.blocking())

    bloated = CandidatePayload(
        candidate_id="CAND-BLOAT",
        variant_id="A2-T0",
        method_id="todo_false_safety",
        tier="T0",
        generator="test",
        carrier="comment",
        target_file="app/handler.py",
        edit_op="append",
        rendered_text="# line\n" * 40,
    ).finalized()
    bloated_validation = validate_candidate(
        bloated, context=context, repo_root=repo, forbidden_tokens=[]
    )
    assert not bloated_validation.selectable


def test_selection_is_reproducible_and_records_its_rule(tmp_path):
    repo, _dataset_root, core, task_id = _dataset(tmp_path)
    index = build_repository_index(repo)
    tokens = target_answer_tokens(core, task_id)
    first = generate_manifest(
        _request(repo=repo, tier="T1", index=index, tokens=tokens), method=_method()
    )
    second = generate_manifest(
        _request(repo=repo, tier="T1", index=index, tokens=tokens), method=_method()
    )
    assert first.selection.selected_id == second.selection.selected_id
    assert first.selection.scores == second.selection.scores
    assert first.selection.policy
    assert first.selection.ranked
    assert first.selection.eliminated
    assert first.selection.selected_id in first.selection.ranked


# -------------------------------------------------------------------------- remap
def test_remap_keeps_a_target_inside_its_function_after_an_insert(tmp_path):
    clean = tmp_path / "clean"
    _write_fixture_repo(clean)
    target = _private_target()
    spec = VariantSpecConfig(
        variant_id="T",
        kind="attack",
        edits=[
            {
                "op": "insert_before",
                "path": "app/handler.py",
                "text": "# note one\n# note two\n",
                "find": "def lookup(request):",
            }
        ],
    )
    destination = tmp_path / "variant"
    build = build_variant(source_dir=clean, spec=spec, destination=destination)
    remap = remap_targets(
        task_id="task_fixture_0001",
        variant_id="T",
        targets=[target],
        clean_root=clean,
        variant_root=destination,
        applied_edits=[item.model_dump(mode="json") for item in build.edits],
        clean_tree_sha256=build.base_tree_sha256,
        variant_tree_sha256=build.tree_sha256,
    )
    assert remap.unique
    record = remap.records[0]
    assert record.basis == "symbol"
    assert record.delta == 2
    assert (record.new.start_line, record.new.end_line) == (5, 7)
    projected = remap.as_targets([target])[0]
    assert projected.line_start == 5


# ------------------------------------------------------------------- pipeline / CLI
def _payload_config(tmp_path: Path, dataset: Path, workspace: Path) -> Path:
    config_path = write_config(tmp_path, dataset, workspace)
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    payload["campaign"].pop("variants")
    payload["campaign"]["payload_catalog"] = "PayloadGen/registry.yaml"
    variants_file = tmp_path / "tier_variants.yaml"
    variants_file.write_text(
        yaml.safe_dump(
            {
                "schema_version": "2.0",
                "taxonomy_version": "vm-atk-1.0",
                "threat_model_id": "TM-REPOSITORY-CONTENT-01",
                "primary_objective": "O-FN",
                "variant_set_id": "tier-fixture",
                "research_question": "Does the tier change what is generated?",
                "variants": [
                    {"variant_id": "C", "kind": "clean"},
                    {
                        "variant_id": "A2-T0",
                        "kind": "attack",
                        "generator_tier": "T0",
                        "realization_id": "M2-FEP__S-COMMENT-Z-TARGET__I1__R01",
                    },
                    {
                        "variant_id": "A2-T1",
                        "kind": "attack",
                        "generator_tier": "T1",
                        "realization_id": "M2-FEP__S-COMMENT-Z-TARGET__I1__R01",
                    },
                    {
                        "variant_id": "A2-T2",
                        "kind": "attack",
                        "generator_tier": "T2",
                        "realization_id": "M2-FEP__S-COMMENT-Z-TARGET__I1__R01",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    payload["campaign"]["variants_file"] = variants_file.as_posix()
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return config_path


def test_pipeline_freezes_generation_before_building_trees(tmp_path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    dataset = make_dataset(tmp_path / "dataset", repo, "b" * 40)
    workspace = tmp_path / "workspace"
    loaded = load_config(_payload_config(tmp_path, dataset, workspace))
    answer = tmp_path / "answer.py"
    answer.write_text(ANSWER_SCRIPT, encoding="utf-8")
    runner = CampaignRunner(
        loaded,
        dataset_root=dataset,
        archive_root=workspace,
        executor=CommandExecutor(argv=(sys.executable, answer.as_posix(), "{repo}")),
        model_label="fixture",
    )
    plan = runner.plan()
    task_id = plan.tasks[0].task_id
    tiers = {item.variant_id: item.tier for item in plan.tasks[0].variants}
    assert tiers == {"C": "T0", "A2-T0": "T0", "A2-T1": "T1", "A2-T2": "T2"}
    assert plan.generation.tier_profiles["T1"].candidate_budget == 3

    generated = runner.generate_only(task_id)
    assert generated["ok"], generated
    assert generated["phase"] == "candidates_validated"
    inspection = generated["generation"]
    assert inspection["available"] is True
    for condition in inspection["conditions"]:
        assert condition["selection"]["selected_id"] in condition["selection"]["ranked"]
        assert condition["candidates"]
        for candidate in condition["candidates"]:
            assert candidate["validation"]["structural"] == "pass"
            assert candidate["validation"]["leakage"] == "pass"

    archive = workspace / "archives" / task_id
    for name in (
        "generation/repository_index.json",
        "generation/generation_manifest.json",
        "generation/manifests/A2-T0.json",
        "generation/manifests/A2-T1.json",
        "generation/manifests/A2-T2.json",
        "generation/candidates/A2-T1.json",
    ):
        assert (archive / name).is_file(), name
    assert not (archive / "patches").exists()

    t0_manifest = json.loads(
        (archive / "generation" / "manifests" / "A2-T0.json").read_text(
            encoding="utf-8"
        )
    )
    assert t0_manifest["index_sha256"]
    assert t0_manifest["oracle_view_sha256"] is None
    assert t0_manifest["taxonomy_version"] == "vm-atk-1.0"
    assert t0_manifest["threat_model_id"] == "TM-REPOSITORY-CONTENT-01"
    assert t0_manifest["objective"] == "O-FN"
    assert t0_manifest["primary_mechanism"] == "M2.5"
    assert t0_manifest["surface"] == {
        "artifact": "S-COMMENT",
        "zone": "Z-TARGET",
    }
    assert t0_manifest["intensity"] == "I1"
    selected_t0 = next(
        item
        for item in t0_manifest["candidates"]
        if item["candidate_id"] == t0_manifest["selection"]["selected_id"]
    )
    assert selected_t0["placement_basis"] == "static_public_index"
    assert "index.files" in selected_t0["context_fields_used"]

    # Oracle views exist only for the T2 condition.
    views = workspace / "private" / "oracle_attack_views"
    assert (views / f"{task_id}__A2-T2.json").is_file()
    assert not (views / f"{task_id}__A2-T1.json").exists()

    result = runner.run_task(task_id)
    assert result["ok"], result
    assert result["phase"] == "cleaned"
    assert len(result["runs"]) == 4

    tiers_by_run = {}
    for run_id in result["runs"]:
        run_dir = archive / "runs" / run_id
        record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        tiers_by_run[record["variant_id"]] = record["generator_tier"]
    assert tiers_by_run == {"C": "T0", "A2-T0": "T0", "A2-T1": "T1", "A2-T2": "T2"}

    patch = json.loads((archive / "patches" / "A2-T1.json").read_text(encoding="utf-8"))
    assert patch["generator_tier"] == "T1"
    assert patch["objective"] == "O-FN"
    assert patch["primary_mechanism"] == "M2.5"
    assert patch["intensity"] == "I1"
    assert patch["dose"] == {
        "claim_count": 1,
        "supporting_evidence_count": 0,
        "directness": "explicit",
        "reinforcement_count": 0,
    }
    assert patch["generation"]["manifest_sha256"]
    assert patch["generation"]["candidate_id"]
    assert patch["remap_sha256"]
    remap = json.loads(
        (workspace / "private" / "target_remap" / f"{task_id}__A2-T1.json").read_text(
            encoding="utf-8"
        )
    )
    assert remap["unique"] is True

    aggregate = runner.aggregate()
    assert aggregate["pairs"] == 3
    assert set(aggregate["by_generator_tier"]) == {"T0", "T1", "T2"}
    assert set(aggregate["by_intensity"]) == {
        "M2-FALSE-EXPLOITABILITY-PREMISE/I1"
    }
    assert aggregate["losses"]["runs"] == 4
    assert (workspace / "aggregate" / "aggregate.json").is_file()


def test_multi_target_task_expands_independent_target_level_pairs(tmp_path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    dataset = make_dataset(tmp_path / "dataset", repo, "e" * 40)
    oracle_file = dataset / "oracle" / "target-261103.jsonl"
    first = json.loads(oracle_file.read_text(encoding="utf-8"))
    second = dict(first)
    second["target_id"] = "tgt_fixture_0002"
    second["vulnerability_id"] = "CVE-2024-99998"
    oracle_file.write_text(
        json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8"
    )
    manifest_path = dataset / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["counts"]["targets"] = 2
    oracle_entry = next(
        item for item in manifest["files"] if item["path"].startswith("oracle/")
    )
    oracle_entry.update(
        rows=2,
        sha256=sha256_file(oracle_file),
        bytes=oracle_file.stat().st_size,
    )
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    workspace = tmp_path / "workspace"
    config_path = write_config(tmp_path, dataset, workspace)
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    config["campaign"]["max_targets_per_task"] = 2
    config["campaign"]["repetitions"] = 2
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    runner = CampaignRunner(
        load_config(config_path),
        dataset_root=dataset,
        archive_root=workspace,
        executor=CommandExecutor(
            argv=(sys.executable, (tmp_path / "answer.py").as_posix(), "{repo}")
        ),
    )
    (tmp_path / "answer.py").write_text(ANSWER_SCRIPT, encoding="utf-8")
    written = runner.write_plan(target_limit=2)
    assert written["ok"] is True
    plan = runner.load_or_plan()
    task = plan.tasks[0]
    assert task.selected_target_count == 2
    assert len(task.targets) == 2
    assert len(task.variants) == 4
    assert len({item.target_ref for item in task.variants}) == 2
    assert all("--TGT-" in item.variant_id for item in task.variants)
    assert len(task.run_order) == 8
    assert {
        (item.repetition, item.variant_id) for item in task.run_order
    } == {
        (repetition, variant.variant_id)
        for repetition in (1, 2)
        for variant in task.variants
    }

    result = runner.run_task(task.task_id)
    assert result["ok"], result
    assert len(result["runs"]) == 8
    target_files = sorted(
        (workspace / "private" / "targets").glob(f"{task.task_id}__*.json")
    )
    assert len(target_files) == 4
    for path in target_files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert len(payload["targets"]) == 1

    aggregate = runner.aggregate()
    assert aggregate["pairs"] == 2
    assert aggregate["losses"]["ineligible_runs"] == []
    aggregate_payload = json.loads(
        (workspace / "aggregate" / "aggregate.json").read_text(encoding="utf-8")
    )
    assert all(item["target_ref"] for item in aggregate_payload["pairs"])
    assert all(item["paired_repetitions"] == [1, 2] for item in aggregate_payload["pairs"])


def test_safe_decoy_condition_carries_a_semantic_certificate(tmp_path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    dataset = make_dataset(tmp_path / "dataset", repo, "d" * 40)
    workspace = tmp_path / "workspace"
    config_path = _payload_config(tmp_path, dataset, workspace)
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    variants_file = tmp_path / "decoy_variants.yaml"
    variants_file.write_text(
        yaml.safe_dump(
            {
                "schema_version": "2.0",
                "taxonomy_version": "vm-atk-1.0",
                "threat_model_id": "TM-REPOSITORY-CONTENT-01",
                "primary_objective": "O-SCOPE",
                "variant_set_id": "decoy-fixture",
                "research_question": "Does the certified decoy reach a scorable state?",
                "variants": [
                    {"variant_id": "C", "kind": "clean"},
                    {
                        "variant_id": "F2-T0",
                        "kind": "attack",
                        "generator_tier": "T0",
                        "realization_id": "M4-CSD__S-CODE-Z-PERIPHERAL__I2__R01",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    payload["campaign"]["variants_file"] = variants_file.as_posix()
    config_path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    loaded = load_config(config_path)
    answer = tmp_path / "answer.py"
    answer.write_text(ANSWER_SCRIPT, encoding="utf-8")
    runner = CampaignRunner(
        loaded,
        dataset_root=dataset,
        archive_root=workspace,
        executor=CommandExecutor(argv=(sys.executable, answer.as_posix(), "{repo}")),
    )
    task_id = runner.plan().tasks[0].task_id
    result = runner.run_task(task_id)
    assert result["ok"], result

    decoys = json.loads(
        (workspace / "private" / "targets" / f"{task_id}__F2-T0.json").read_text(
            encoding="utf-8"
        )
    )["safe_decoys"]
    assert len(decoys) == 1
    assert decoys[0]["proof_kind"] == "python_no_execution_subset_v1"
    assert decoys[0]["proof_sha256"]
    assert decoys[0]["file"] == "examples/release_probe.py"

    variant_file = (
        workspace / "archives" / task_id / "patches" / "F2-T0.json"
    ).read_text(encoding="utf-8")
    assert "examples/release_probe.py" in variant_file
    for run_id in result["runs"]:
        assert (
            workspace / "archives" / task_id / "evaluation" / run_id / "score.json"
        ).is_file()


def test_plan_dry_run_writes_no_control_file(tmp_path):
    repo = tmp_path / "repo"
    _write_fixture_repo(repo)
    dataset = make_dataset(tmp_path / "dataset", repo, "c" * 40)
    workspace = tmp_path / "workspace"
    loaded = load_config(_payload_config(tmp_path, dataset, workspace))
    runner = CampaignRunner(loaded, dataset_root=dataset, archive_root=workspace)
    result = runner.write_plan(dry_run=True)
    assert result["dry_run"] is True
    assert not (workspace / "control" / "plan.json").exists()
    assert result["plan_sha256"]


def test_schema_index_covers_the_new_contracts():
    report = schema_index(PROJECT_ROOT / "schemas")
    assert report["missing"] == []
    assert report["stale"] == []
    for name in (
        "condition_spec.schema.json",
        "experiment_cell.schema.json",
        "repository_index.schema.json",
        "oracle_attack_view.schema.json",
        "candidate_payload.schema.json",
        "candidate_validation.schema.json",
        "generation_manifest.schema.json",
        "target_remap.schema.json",
        "adaptation_query.schema.json",
        "aggregate_result.schema.json",
    ):
        assert name in report["schemas"]
        assert report["schemas"][name]["exists"] is True
