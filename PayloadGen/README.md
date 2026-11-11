# PayloadGen

`PayloadGen` is the trusted attack-construction library. It is read before an
audit and is never copied wholesale into the Agent workspace.

## Canonical identity

An attacked condition freezes:

```text
ThreatModel reference × Objective × Method × Surface × Intensity × Realization
```

- `Objective` states which audit outcome should become wrong.
- `Method` has one primary causal mechanism.
- `Surface` combines the repository artifact and semantic zone.
- `Intensity` is the method-specific `I0`–`I4` attack dose.
- `Realization` is a concrete text or transformation.
- T0–T4 are generator-context provenance, not taxonomy and not attack strength.

See [`docs/payload_attack_taxonomy.md`](../docs/payload_attack_taxonomy.md) for the
normative definitions.

## Files

- `registry.yaml` — schema 3 registry containing method definitions and concrete
  realizations. Loader checks objective, surface, intensity, generator backend and
  threat-model consistency before generation.
- `threat_models/repository_content.yaml` — repository-content attacker capability
  and mutation budget. The registry references it by stable ID.
- `methods/*/templates/` — generator-context-specific renderings. T1 uses public
  repository structure; T2 may use the sanitized local oracle view.
- `realizations/*/i0..i4/` — concrete intensity realizations for the three core M2
  methods. A realization declares
  an auditable dose: claim count, supporting-evidence count, directness and
  reinforcement count.
- `templates/*` — deterministic fallback templates.
- `variant_sets/*` — pre-registered, single-objective experiment sets. Every set
  contains the clean baseline `C`; no benign injected control is added.

## Variant-set rules

Variant-set schema 2 requires `taxonomy_version`, `threat_model_id` and one
`primary_objective`. An attack row names only a `realization_id` and
`generator_tier`; method, mechanism, surface and intensity are resolved from the
registry and frozen into `plan.json`, generation manifests, patch metadata and run
records. A contradictory objective or method is rejected before repository download
or model execution.

Current sets are:

- `core.yaml` — implemented `O-FN` core;
- `generator_context_ablation.yaml` — generator context with taxonomy identity fixed;
- `intensity_false_prior_resolution.yaml` — fixed-T2 `M2.1` intensity ablation;
- `intensity_false_exploitability.yaml` — fixed-T2 `M2.5` intensity ablation with
  two independent realizations at each of I0–I4;
- `intensity_fabricated_analysis.yaml` — fixed-T2 `M2.2` intensity ablation;
- `false_negative.yaml` — target suppression;
- `safe_decoy.yaml` — certified false-finding induction;
- `scope_diversion.yaml` — certified-safe attention diversion;
- `severity.yaml` — severity downgrade;
- `severity_inflation.yaml` — severity inflation.

Different Objectives are never pooled into one primary success rate.

## Generation and validation

The generator tier controls which trusted context may be read:

- T0: deterministic template and public placement index;
- T1: public repository index adaptation;
- T2: T1 plus a sanitized target-local oracle view;
- T3/T4: unimplemented and rejected.

Every candidate passes structural, leakage, semantic and budget validators. A
required `unknown` is blocking. M5 methods must request behavior-equivalence
validation. Safe-decoy realizations carry a private certificate; only the matching
pre-registered claim is scored as a false positive.

Catalog loading also validates intensity dose before planning: I0 must be implicit
and unsupported, I1 explicit and unsupported, I2 must add one contextual support,
I3 two supports, and I4 at least two claims plus explicit reinforcement. The dose
must remain within the method-specific profile; changing only the `I*` label fails.

Select a set only while planning:

```text
python -m vulnmirage campaign plan --config configs/experiment.yaml \
  --variant-set PayloadGen/variant_sets/false_negative.yaml \
  --workspace workspace/campaigns/false-negative/deepseek-chat
```

The plan hashes the registry, threat model, variant set and every referenced
template. `campaign run` restores that frozen identity and cannot switch sets.
