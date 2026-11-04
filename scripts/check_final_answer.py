# -*- coding: utf-8 -*-
"""检查一次 run 的"最终答案"是否合规（不跑模型、不下载、不写 workspace）。

用途：run 之后立刻判断「有没有拿到双输出契约要求的报告 + findings」，而不是等到
评分阶段才发现 format_failure。

    # 检查一次 campaign run 的产物目录（final_raw.txt / findings.json / 一致性）
    python scripts/check_final_answer.py --run-dir workspace/archives/<task>/runs/<run>

    # 直接检查一份答案文件
    python scripts/check_final_answer.py --raw workspace/archives/<task>/runs/<run>/final_raw.txt

    # 从捕获的 stdout（opencode --format json 事件流）里抽答案再检查
    python scripts/check_final_answer.py --stdout workspace/archives/<task>/runs/<run>/stdout.log

    # 合成一份"分段叙述 + 最后一段 JSON"的事件流，自测抽取器
    python scripts/check_final_answer.py --demo

退出码：0 = 合规；1 = 不合规（给出原因与下一步建议）。
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass

from vulnmirage.campaign.executor import extract_final_answer  # noqa: E402
from vulnmirage.evaluation.parser import (  # noqa: E402
    OutputParseError,
    output_consistency,
    parse_agent_output,
)


def _verdict(text: str, *, source: str) -> int:
    try:
        parsed = parse_agent_output(text, require_report=True)
    except OutputParseError as exc:
        print("\n✗ 无法解析为合规答案：%s" % exc.message)
        print("  → 看 stdout.log / agent_report.md 是否只有叙述；检查 prompts/audit_task.md 的")
        print("    OUTPUT CONTRACT 是否被模型忽略；必要时换更服从 JSON 约束的模型配置")
        return 1
    consistency = output_consistency(parsed, require_report=True)
    print("\n答案来源            : %s" % source)
    print("输出契约            : %s" % parsed.output_contract)
    print("findings            : %d 条" % len(parsed.findings))
    print("report_markdown     : %d 字符" % consistency.report_chars)
    print("报告/JSON 一致性    : %s" % consistency.status)
    for note in consistency.notes:
        print("  - %s" % note)
    for finding in parsed.findings[:3]:
        locations = finding.locations or []
        head = locations[0] if locations else None
        print(
            "   · %s | %s | %s:%s"
            % (
                finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
                finding.vulnerability_type,
                head.file if head else "?",
                head.start_line if head else "?",
            )
        )
    if consistency.status in {"consistent", "report_missing"}:
        print("\n✓ 合规（findings 可参与评分）")
        return 0
    print("\n⚠ 可解析但报告与 findings 不一致：评分会记录 divergent，报告级指标不可评估")
    return 0


def _check_run_dir(run_dir: Path) -> int:
    final = run_dir / "final_raw.txt"
    if not final.is_file():
        print("✗ %s 下没有 final_raw.txt：这次 run 没拿到答案" % run_dir)
        return 1
    code = _verdict(final.read_text(encoding="utf-8", errors="replace"), source=final.as_posix())
    findings_path = run_dir / "findings.json"
    if findings_path.is_file():
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
        print("findings.json       : status=%s failed=%s" % (payload.get("status"), payload.get("failed")))
    consistency_path = run_dir / "output_consistency.json"
    if consistency_path.is_file():
        payload = json.loads(consistency_path.read_text(encoding="utf-8"))
        print("落盘一致性记录      : %s" % payload.get("status"))
    return code


def _demo() -> Path:
    events = []
    for note in ("Let me look around.", "Reading the parser."):
        events.append({"type": "text", "sessionID": "ses_demo", "part": {"text": note}})
        events.append(
            {"type": "step_finish", "sessionID": "ses_demo", "part": {"reason": "tool-calls"}}
        )
    answer = {
        "schema_version": "1.0",
        "report_markdown": "## Scope\nReviewed app/main.py.\n\n## F-1 demo\napp/main.py:2.\n",
        "findings": [
            {
                "finding_id": "F-1",
                "title": "demo",
                "vulnerability_type": "SQL injection",
                "cwe": ["CWE-89"],
                "severity": "high",
                "confidence": 0.5,
                "locations": [{"file": "app/main.py", "start_line": 1, "end_line": 2}],
                "entry_point": {"file": "app/main.py", "start_line": 1, "end_line": 2},
                "critical_operation": {"file": "app/main.py", "start_line": 2, "end_line": 2},
                "trace": [{"file": "app/main.py", "start_line": 1, "end_line": 2}],
                "exploitability": "demo",
                "evidence": ["demo"],
            }
        ],
        "audit_summary": {
            "files_reviewed": ["app/main.py"],
            "limitations": [],
            "overall_confidence": 0.5,
        },
    }
    events.append({"type": "text", "sessionID": "ses_demo", "part": {"text": json.dumps(answer, ensure_ascii=False)}})
    events.append({"type": "step_finish", "sessionID": "ses_demo", "part": {"reason": "stop"}})
    path = Path(tempfile.mkdtemp()) / "stdout.log"
    path.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="检查一次 run 的最终答案是否符合双输出契约")
    parser.add_argument("--run-dir", help="campaign run 目录（archives/<task>/runs/<run>）")
    parser.add_argument("--raw", help="答案文件（final_raw.txt）")
    parser.add_argument("--stdout", help="捕获的 stdout 日志（事件流或纯文本）")
    parser.add_argument("--demo", action="store_true", help="合成事件流自测抽取器")
    args = parser.parse_args(argv)

    if args.demo:
        path = _demo()
        print("=== demo：2 段叙述 + 最后一段 JSON 事件流 ===")
        captured = path.read_text(encoding="utf-8")
        extracted = extract_final_answer(captured, strategy="jsonl_events")
        if extracted is None:
            print("✗ 抽取器没有找到答案")
            return 1
        return _verdict(extracted, source="demo stdout")
    if args.run_dir:
        return _check_run_dir(Path(args.run_dir))
    if args.raw:
        return _verdict(Path(args.raw).read_text(encoding="utf-8", errors="replace"), source=args.raw)
    if args.stdout:
        captured = Path(args.stdout).read_text(encoding="utf-8", errors="replace")
        extracted = extract_final_answer(captured, strategy="jsonl_events")
        if extracted is None:
            print("✗ 从 stdout 里抽不到答案：模型可能只输出了叙述")
            return 1
        return _verdict(extracted, source=args.stdout)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
