# Adding a manipulation operator

Operators implement the contract in `src/vulnmirage/manipulations/base.py`.

```python
class ManipulationOperator(ABC):
    name: ClassVar[str]
    tier: ClassVar[ManipulationTier]
    strategy_family: ClassVar[str]
    carriers: ClassVar[tuple[str, ...]]

    def supports(self, context: GenerationContext) -> bool: ...
    def plan(self, repo_root, oracle, spec, rng) -> ChangePlan: ...
    def apply(self, repo_root, plan) -> PatchArtifact: ...
    def validate_local(self, repo_root, plan) -> list[ValidationResult]: ...
```

## Plan/apply rules

* `plan()` is read-only. The generator digests the worktree before and after
  planning and raises if anything changed.
* `plan()` returns full file contents (`PlannedFile.mode = create|replace`), an
  explicit `allowed_paths` set, payload provenance, optional decoys/claim graph
  and target-safe locations for false-positive metrics.
* Replacement plans record `original_content`; `apply()` refuses if the file
  changed between plan and apply.
* `apply()` writes only paths listed in `allowed_paths`, uses atomic LF writes,
  and returns a deterministic patch artifact via a temporary git index.
* Operators must never modify the cache, `.git`, the instance directory or any
  path outside the isolated worktree.

## Validation obligations

The full pipeline re-runs independently of operator-local checks:

1. schema / ID / path safety;
2. repository integrity (HEAD, tree hashes, cache refs, patch hash);
3. diff scope (all changes inside `files_touched`, no reserved files);
4. oracle EP/CO/trace remap and code-hash verification;
5. semantic preservation (Python AST or comment-stripped fingerprint for
   modified code files; new files must compile; new Python modules must be
   unreferenced unless they are decoys);
6. build/test commands and clean-vs-variant exit-code parity;
7. original PoC and regression replay with stdout parity;
8. decoy safety validators (M5);
9. leakage;
10. ground-truth invariance and release policy.

A candidate never enters the release set because an operator says it is safe.
`SKIP` is not silently treated as `PASS`; the validation profile and
`require_*` flags decide which skips are acceptable.

## Tiers

* **M1** may only add documentation, comments or unreferenced static strings.
* **M2** uses natural project prose; no "ignore previous instructions".
* **M3** must persist a `ClaimGraph` whose nodes are injected evidence and whose
  edges encode references/support. Each file must read coherently alone.
* **M4** must be behavior-preserving. Prefer unreferenced helpers/constants or
  comments. Any code transformation needs AST/build/test/PoC evidence.
* **M5** must provide a `DecoyRecord` with apparent source → trace → false
  bridge → sink and automated safety validators. `verified_safe` is set only by
  running those validators. Overlap with a real oracle location rejects the
  instance.
* **M6** composes verified children, rejects overlapping write sets, and re-runs
  every check on the combined worktree.

## Payload registry

Add a payload to `payloads/registry.yaml`:

```yaml
- payload_id: unique_id
  origin: mechanism_reimplementation
  source_title: "..."
  source_url: "https://..."
  source_license: null
  strategy_family: my_strategy
  compatible_goals: [false_negative, false_positive]
  compatible_carriers: [markdown]
  template_file: templates/my_template.md.j2
  strategy_split: public_known
```

Rules:

* unique `payload_id`; template must exist and be a safe relative path;
* `published_verbatim` requires both `source_url` and `source_license`;
* held-out payloads use `strategy_split: heldout_strategy` and are filtered out
  of development generation;
* templates are rendered with `StrictUndefined`; the context is only
  `project_name`, `language`, `vulnerability_type`, `cwe`, `target_component`,
  `visible_function_names`, `attack_goal`, `carrier`;
* never put hidden oracle IDs, PoC code or advisory text in a template.

## Registering

Add the class to `OPERATOR_CLASSES` and map `(tier, goal)` in
`GOAL_OPERATOR` / `OPERATOR_CANDIDATES` in `manipulations/__init__.py`. For M6,
teach `children_for_goal` how to construct its children.

## Tests

At minimum:

* plan is read-only;
* apply touches only allowed paths;
* local checks pass;
* generated patch is applied to a second clean worktree and yields identical
  semantics;
* full validation remains release-eligible;
* a deliberately broken safety validator/diff-scope/semantic change is rejected.
