# Leakage channels: control and verification

A benchmark that removes one `oracle.json` still leaks the answer through Git
history, the hosted fix commit, the task identifier or a reused session directory.
This document lists the channels, the control applied to each, and the check that
has to pass for the channel to be called *controlled*.

Two rules make the table usable:

1. **A channel is controlled because a check ran and passed.** A configuration
   value (`oracle_mounted: false`) is a claim. The registry in
   `src/vulnmirage/isolation/channels.py` binds each channel to attestation check
   ids, and `leakage_controls.json` reports `controlled` / `failed` / `unknown` per
   run. A channel with no executed check is `unknown`, never `controlled`.
2. **The channels come from published enumerations, the checks come from here.**
   SWE-Bench Pro Verified enumerates reference-answer channels, CyberGym documents
   the network shortcut, Terminal-Bench separates agent and verifier environments.
   Adopting their lists is not evidence that this package closes them.

## The matrix

| Channel | Why it leaks | Control | Verification |
| --- | --- | --- | --- |
| Local oracle, validation logs, previous reports | readable next to the workspace | the oracle is never written under the campaign root; scoring reads it from the dataset package in the verifier | `oracle_files_absent` |
| Fix commit, future Git objects, nested history | a clone ships later commits and the fix | one exact-commit archive is unpacked; no `.git`; nested history is refused by default | `history_absent`, `archive_scan` |
| Hosted dataset, advisory search, fix lookup | the repository and the CVE are public | tools are offline by policy and by environment; one inference gateway; live egress probe | `egress_blocked`, `inference_gateway` |
| Task prompt, instance name, manifest labels | the prompt names repo, commit, tag, CWE | field whitelist and prompt normalization, then a re-scan of the result | `prompt_scan` |
| Session cache, previous score | a reused state dir carries the earlier conversation | a fresh state directory per run, asserted empty; scores never written into the workspace | `fresh_state` |
| Parent directory, sibling variants | a diff against the clean tree reveals the injection | variant trees stay in the preparation area; one variant is copied per run and removed afterwards | `no_sibling_runs`, `repo_tree_matches_variant` |
| Evaluator files, admin endpoints, scoring service | the agent shapes the answer to the metric | verifier runs from the private area on a frozen bundle; roots are proven disjoint | `private_paths_outside_exposed`, `verifier_guard` |
| Report text entering scoring | the report tries to instruct or execute inside the judge | report is bounded, control characters stripped, fenced as data, never executed; sink scan over the verifier source | `verifier_guard` |
| Upstream test suite | it is legitimate audit material | kept as-is; only benchmark-added material is hidden | `archive_scan` |

### What is deliberately *not* removed

The repository's own tests, docs and comments stay. They are what an auditor is
supposed to read, and deleting every test to "isolate" the benchmark would make the
audit task unrealistic. Only material the benchmark itself adds — private PoC, fix
patch, answer labels — is withheld.

## Always on, in every condition

Oracle isolation, workspace containment, egress probing and a fresh state are
**run invariants, not experimental conditions**. They execute for the clean
baseline and for every injected variant, and they are
recorded with `condition_independent: true` in each `isolation_attestation.json`.

The reason is methodological: if only the defended arm received a sealed oracle,
a difference between arms could come from answer reachability instead of the
treatment. A run whose invariants fail is marked ineligible; it is never counted as
an attack success or a defence failure.

## What the checks can and cannot prove

| Claim | Status |
| --- | --- |
| The exposed tree is one variant, without `.git` | proved by hashing and walking the tree |
| The oracle is not under the campaign root | proved by directory walk |
| The bundle carries no oracle | proved by name and content scan |
| Answer hosts are unreachable | **probed**, so proved only for the probed hosts at that moment |
| Host filesystem is a boundary | **not** proved in `subprocess` mode; recorded as `unknown` unless the run is in a container |
| The model did not memorize the advisory | not addressable by any control here |

Domain lists are incomplete by construction — that limitation is reported in
`residual_risk` for the channel instead of being omitted. The honest consequence:
the egress probe raises the bar and makes shortcuts visible, it does not close the
training-data channel.

## Verifying a package

```bash
# channels for a finished task: what ran, what passed, what stayed unknown
python -c "import json;print(json.load(open('workspace/archives/<task>/leakage_controls.json'))['counts'])"

# the raw per-run evidence
python -c "import json;d=json.load(open('workspace/archives/<task>/runs/<run>/isolation_attestation.json'));print(d['verdict'], d['failed'], d['unknown'])"

# the evaluator's own boundary record
cat workspace/archives/<task>/evaluation/<run>/verifier_attestation.json
```
