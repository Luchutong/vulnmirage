"""OpenCode adapter built on the generic subprocess runner.

Final-answer extraction is deliberately conservative (P0-4):

* raw JSONL events are preserved as the native trace;
* only assistant *text* events are candidates — tool results and intermediate
  narration are never concatenated into the report;
* when several text events carry a finding envelope, all must be identical;
  otherwise the output is ``ambiguous`` and is not scored;
* unknown event shapes degrade to ``unsupported`` instead of guessing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..config import AgentConfig
from ..models import AgentRun
from ..store import InstanceStore
from .base import PreparedRun
from .subprocess_agent import SubprocessAgentAdapter, expand_argv

#: Event shape documented for the verified OpenCode version.
SUPPORTED_EVENT_FORMAT = "jsonl:type=text,part.text"
_KNOWN_EVENT_TYPES = {
    "text",
    "tool",
    "tool_call",
    "tool_result",
    "step_start",
    "step_finish",
    "reasoning",
    "error",
    "session",
    "message",
}


@dataclass
class FinalAnswerResult:
    status: str  # ok | unsupported | ambiguous | format_failure
    final_text: str | None
    event_count: int = 0
    text_event_count: int = 0
    envelope_candidates: int = 0
    unknown_event_types: list[str] = field(default_factory=list)
    reason: str | None = None
    raw_events_path: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == "ok" and self.final_text is not None


def _looks_like_finding_envelope(text: str) -> bool:
    from ..evaluation.parser import extract_json_objects

    for payload in extract_json_objects(text):
        if isinstance(payload, dict) and "findings" in payload:
            return True
    return False


def _normalized(text: str) -> str:
    return " ".join(text.split())


def split_json_stream_result(
    stdout_path: Path,
    trace_path: Path,
    *,
    event_format: str | None = None,
) -> FinalAnswerResult:
    """Split an OpenCode JSONL stream into raw events and one final answer."""
    stdout_path = Path(stdout_path)
    if not stdout_path.is_file():
        return FinalAnswerResult(
            status="format_failure", final_text=None, reason="stdout_missing"
        )
    expected = event_format or SUPPORTED_EVENT_FORMAT
    if expected != SUPPORTED_EVENT_FORMAT:
        return FinalAnswerResult(
            status="unsupported",
            final_text=None,
            reason=f"unsupported_event_format:{expected}",
        )
    event_lines: list[str] = []
    text_parts: list[str] = []
    unknown_types: set[str] = set()
    for line in stdout_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            # Non-JSON noise is preserved in the raw stream but never used as
            # the final answer.
            event_lines.append(line)
            unknown_types.add("non_json_line")
            continue
        if not isinstance(payload, dict) or "type" not in payload:
            event_lines.append(line)
            unknown_types.add("untyped_json")
            continue
        event_lines.append(line)
        event_type = str(payload.get("type"))
        if event_type not in _KNOWN_EVENT_TYPES:
            unknown_types.add(event_type)
            continue
        if event_type != "text":
            continue
        part = payload.get("part")
        if not isinstance(part, dict) or not part.get("text"):
            continue
        if part.get("type") in {"tool", "tool_result"} or part.get("tool"):
            # Tool output can contain decoy JSON/findings; never the answer.
            continue
        text_parts.append(str(part["text"]))
    if event_lines:
        Path(trace_path).write_text("\n".join(event_lines) + "\n", encoding="utf-8")
    if not event_lines:
        return FinalAnswerResult(
            status="format_failure", final_text=None, reason="no_events"
        )
    envelopes = [text for text in text_parts if _looks_like_finding_envelope(text)]
    base = FinalAnswerResult(
        status="ok",
        final_text=None,
        event_count=len(event_lines),
        text_event_count=len(text_parts),
        envelope_candidates=len(envelopes),
        unknown_event_types=sorted(unknown_types),
        raw_events_path=str(trace_path),
    )
    if envelopes:
        distinct = {_normalized(text) for text in envelopes}
        if len(distinct) > 1:
            base.status = "ambiguous"
            base.reason = f"multiple_distinct_finding_envelopes:{len(distinct)}"
            return base
        base.final_text = envelopes[-1]
        return base
    if len(text_parts) == 1:
        # One text part without an envelope: let the schema parser reject it
        # with a precise format error instead of inventing a report.
        base.final_text = text_parts[0]
        return base
    if not text_parts:
        base.status = "format_failure"
        base.reason = "no_assistant_text_event"
        return base
    base.status = "ambiguous"
    base.reason = f"multiple_text_events_without_envelope:{len(text_parts)}"
    return base


def split_json_stream(stdout_path: Path, trace_path: Path) -> str | None:
    """Backward-compatible wrapper returning only the selected final text."""
    return split_json_stream_result(stdout_path, trace_path).final_text


class OpenCodeAdapter(SubprocessAgentAdapter):
    final_answer_status: str | None = None
    final_answer_notes: list[str] = []

    def build_command(self, prepared: PreparedRun, mapping: dict[str, str]) -> list[str]:
        if self.agent_config.argv:
            return expand_argv(self.agent_config.argv, mapping)
        model = self.agent_config.model or "opencode/default"
        argv = [
            self.agent_config.executable,
            "run",
            "--model",
            model,
        ]
        if self.agent_config.output_format == "json":
            argv.extend(["--format", "json"])
        argv.extend(self.agent_config.extra_args)
        argv.append(mapping["prompt"])
        return argv

    def collect(self, prepared: PreparedRun, raw) -> AgentRun:
        answer_status = None
        answer_notes: list[str] = []
        if self.agent_config.output_format == "json":
            stdout = prepared.run_dir / "stdout.log"
            result = split_json_stream_result(
                stdout,
                prepared.trace_path,
                event_format=self.agent_config.opencode_event_format,
            )
            self.final_answer_status = result.status
            answer_notes = [item for item in [result.reason] if item]
            if result.ok:
                prepared.output_path.write_text(
                    result.final_text or "", encoding="utf-8"
                )
            else:
                # Keep the raw stream; do not feed arbitrary stdout to the
                # report parser.
                answer_status = result.status
                if result.final_text is not None:
                    prepared.output_path.write_text(result.final_text, encoding="utf-8")
        run = super().collect(prepared, raw)
        update: dict[str, object] = {
            "scaffold": "opencode",
            "scaffold_version": self.agent_config.scaffold_version,
            "model_provider": self.agent_config.model_provider,
            "model_name": self.agent_config.model_name,
            "model_version": self.agent_config.model_version,
        }
        if answer_status in {"ambiguous", "unsupported"}:
            update["status"] = "format_failure"
            run = run.model_copy(update=update)
            run = run.model_copy(
                update={
                    "tool_policy": {
                        **run.tool_policy,
                        "final_answer_status": answer_status,
                        "final_answer_notes": answer_notes,
                    }
                }
            )
            return run
        return run.model_copy(update=update)
