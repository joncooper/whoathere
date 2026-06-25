#!/usr/bin/env python3
"""Export a Codex JSONL session to a sanitized, navigable HTML transcript."""

from __future__ import annotations

import argparse
import html
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from textwrap import shorten
from typing import Any
from zoneinfo import ZoneInfo


REDACTIONS = [
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "sk-[REDACTED]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"), "gh[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AKIA[REDACTED]"),
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
        "jwt.[REDACTED]",
    ),
    (re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}", re.I), "Bearer [REDACTED]"),
    (
        re.compile(
            r"(?i)((?:api[_-]?key|access[_-]?token|auth[_-]?token|github[_-]?token|openai[_-]?api[_-]?key|password|secret)\s*[:=]\s*)[^\s,;\"']{8,}"
        ),
        r"\1[REDACTED]",
    ),
]


SOURCE_DEFAULT = Path(
    "/Users/jdc/.codex/sessions/2026/06/24/"
    "rollout-2026-06-24T20-48-17-019efc3f-c19e-7630-bce2-669356258a5c.jsonl"
)
OUTPUT_DEFAULT = Path(
    "/Users/jdc/src/whoathere/docs/whoathere/design-whoathere-architecture-thread.html"
)

USER_MILESTONE_LABELS = {
    1: "Initial architecture brief",
    2: "Implement meta-plan",
    3: "Confirm result",
    4: "Add completion checklist",
    5: "Comprehensive review",
    6: "Run remediation goal",
    7: "Overnight kickoff",
    8: "10-hour run",
    9: "Quality bar",
    10: "Resume goal",
    11: "Usage limit note",
    12: "Transient issue cleared",
    13: "Usage note",
    14: "Pause request",
    15: "Progress check",
}


@dataclass
class Event:
    kind: str
    timestamp: str
    title: str
    body: str = ""
    details: str = ""
    phase: str = ""
    anchor: str = ""


def redact(text: Any) -> str:
    if text is None:
        return ""
    value = str(text)
    value = value.replace("/Users/jdc", "~")
    for pattern, replacement in REDACTIONS:
        value = pattern.sub(replacement, value)
    return value


def esc(text: Any) -> str:
    return html.escape(redact(text), quote=True)


def local_time(iso_timestamp: str, zone: ZoneInfo) -> str:
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return iso_timestamp
    return dt.astimezone(zone).strftime("%b %-d, %-I:%M:%S %p %Z")


def compact_time(iso_timestamp: str, zone: ZoneInfo) -> str:
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return iso_timestamp
    return dt.astimezone(zone).strftime("%-I:%M %p")


def duration_label(seconds: float) -> str:
    seconds = max(0, int(seconds))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def timestamp_seconds(iso_timestamp: str) -> float | None:
    try:
        return datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def milestone_label(kind: str, index: int, text: str) -> str:
    if kind == "user":
        return USER_MILESTONE_LABELS.get(index, f"User input {index}")
    return preview(text, 44)


def checkpoint_label(index: int, text: str) -> str:
    for line in text.splitlines():
        cleaned = line.strip().strip("*#` ")
        if cleaned:
            return f"Checkpoint {index}: {shorten(cleaned, width=32, placeholder='...')}"
    return f"Checkpoint {index}"


def safe_href(href: str) -> str:
    href = redact(href).strip()
    if href.startswith(("http://", "https://", "#", "/", "./", "../", "mailto:")):
        return href
    return "#"


def render_inline_markdown(text: str) -> str:
    code_spans: list[str] = []

    def stash_code(match: re.Match[str]) -> str:
        code_spans.append(f"<code>{esc(match.group(1))}</code>")
        return f"@@CODE{len(code_spans) - 1}@@"

    rendered = re.sub(r"`([^`]+)`", stash_code, text)
    rendered = esc(rendered)

    def link(match: re.Match[str]) -> str:
        label = match.group(1)
        href = safe_href(match.group(2))
        return f'<a href="{esc(href)}">{esc(label)}</a>'

    rendered = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", link, rendered)
    rendered = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", rendered)
    rendered = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", rendered)
    for index, span in enumerate(code_spans):
        rendered = rendered.replace(f"@@CODE{index}@@", span)
    return rendered


def render_markdown(text: str) -> str:
    lines = redact(text).splitlines()
    blocks: list[str] = []
    paragraph: list[str] = []
    list_items: list[str] = []
    list_type: str | None = None
    in_code = False
    code_lang = ""
    code_lines: list[str] = []

    def flush_paragraph() -> None:
        nonlocal paragraph
        if paragraph:
            blocks.append(f"<p>{render_inline_markdown(' '.join(paragraph))}</p>")
            paragraph = []

    def flush_list() -> None:
        nonlocal list_items, list_type
        if list_items and list_type:
            body = "".join(f"<li>{render_inline_markdown(item)}</li>" for item in list_items)
            blocks.append(f"<{list_type}>{body}</{list_type}>")
        list_items = []
        list_type = None

    for line in lines:
        if line.startswith("```"):
            if in_code:
                blocks.append(
                    f'<pre><code class="language-{esc(code_lang)}">{esc(chr(10).join(code_lines))}</code></pre>'
                )
                in_code = False
                code_lang = ""
                code_lines = []
            else:
                flush_paragraph()
                flush_list()
                in_code = True
                code_lang = line.strip("` ").strip()
            continue
        if in_code:
            code_lines.append(line)
            continue

        stripped = line.strip()
        if not stripped:
            flush_paragraph()
            flush_list()
            continue

        heading = re.match(r"^(#{1,4})\s+(.+)$", stripped)
        if heading:
            flush_paragraph()
            flush_list()
            level = min(4, len(heading.group(1)) + 2)
            blocks.append(f"<h{level}>{render_inline_markdown(heading.group(2))}</h{level}>")
            continue

        bullet = re.match(r"^[-*]\s+(.+)$", stripped)
        numbered = re.match(r"^\d+\.\s+(.+)$", stripped)
        if bullet or numbered:
            flush_paragraph()
            new_type = "ul" if bullet else "ol"
            if list_type and list_type != new_type:
                flush_list()
            list_type = new_type
            list_items.append((bullet or numbered).group(1))
            continue

        quote = re.match(r"^>\s?(.+)$", stripped)
        if quote:
            flush_paragraph()
            flush_list()
            blocks.append(f"<blockquote>{render_inline_markdown(quote.group(1))}</blockquote>")
            continue

        paragraph.append(stripped)

    if in_code:
        blocks.append(f'<pre><code>{esc(chr(10).join(code_lines))}</code></pre>')
    flush_paragraph()
    flush_list()
    return "\n".join(blocks)


def content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") in {"input_text", "output_text", "text"}:
            parts.append(item.get("text", ""))
    return "\n".join(part for part in parts if part)


def parse_args_json(arguments: Any) -> Any:
    if isinstance(arguments, dict):
        return arguments
    if not isinstance(arguments, str):
        return arguments
    try:
        return json.loads(arguments)
    except json.JSONDecodeError:
        return arguments


def preview(text: str, width: int = 120) -> str:
    flat = " ".join(redact(text).split())
    return shorten(flat, width=width, placeholder="...")


def output_status(output: str) -> str:
    code = re.search(r"(?:Process exited with code|Exit code):?\s*(-?\d+)", output)
    if code:
        return f"exit {code.group(1)}"
    if "Success. Updated the following files:" in output:
        return "patch applied"
    if output.strip():
        return "completed"
    return "no output"


def summarize_tool(name: str, arguments: Any, output: str) -> tuple[str, str, str]:
    args = parse_args_json(arguments)
    title = name
    body = ""
    if name == "exec_command" and isinstance(args, dict):
        cmd = args.get("cmd", "")
        title = "Command"
        body = f"$ {preview(cmd, 220)}"
    elif name == "spawn_agent" and isinstance(args, dict):
        title = "Spawned Subagent"
        role = args.get("role") or args.get("agent_role") or "subagent"
        task = args.get("task") or args.get("prompt") or ""
        body = f"{role}: {preview(task, 220)}"
    elif name in {"wait_agent", "close_agent", "update_plan", "get_goal", "update_goal"}:
        title = name.replace("_", " ").title()
        body = preview(json.dumps(args, ensure_ascii=False), 220)
    else:
        body = preview(json.dumps(args, ensure_ascii=False), 220)

    status = output_status(output)
    if status:
        body = f"{body} [{status}]" if body else status

    detail_parts = []
    if args:
        detail_parts.append("Arguments:\n" + json.dumps(args, ensure_ascii=False, indent=2))
    if output:
        cleaned = redact(output)
        if len(cleaned) > 1200:
            cleaned = cleaned[:1200] + "\n... [truncated in sanitized export]"
        detail_parts.append("Output:\n" + cleaned)
    return title, body, "\n\n".join(detail_parts)


def summarize_custom_tool(name: str, payload: dict[str, Any], output: str = "") -> tuple[str, str, str]:
    title = name.replace("_", " ").title()
    body = ""
    if name == "apply_patch":
        title = "File Patch"
        body = "Patch applied" if "Success. Updated" in output else "Patch prepared"
    detail = ""
    if payload.get("input"):
        patch = redact(payload["input"])
        if len(patch) > 1000:
            patch = patch[:1000] + "\n... [patch truncated in sanitized export]"
        detail += "Patch:\n" + patch
    if output:
        cleaned = redact(output)
        if len(cleaned) > 1200:
            cleaned = cleaned[:1200] + "\n... [truncated in sanitized export]"
        detail += ("\n\n" if detail else "") + "Output:\n" + cleaned
        files = [
            line.strip()
            for line in output.splitlines()
            if re.match(r"^[AMDR]\s+.+", line.strip())
        ]
        if files:
            body = ", ".join(files[:4])
            if len(files) > 4:
                body += f", +{len(files) - 4} more"
    return title, body, detail


def append_subagent_results(
    events: list[Event],
    timestamp: str,
    name: str,
    args: Any,
    output: str,
    agent_by_id: dict[str, dict[str, str]],
    completed_agents: set[str],
) -> None:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return

    results: list[tuple[str, str]] = []
    if isinstance(data, dict) and isinstance(data.get("status"), dict):
        for agent_id, status in data["status"].items():
            if isinstance(status, dict) and status.get("completed"):
                results.append((agent_id, status["completed"]))
    if isinstance(data, dict) and isinstance(data.get("previous_status"), dict):
        target = args.get("target") if isinstance(args, dict) else None
        completed = data["previous_status"].get("completed")
        if target and completed:
            results.append((target, completed))

    for agent_id, completed in results:
        if agent_id in completed_agents:
            continue
        completed_agents.add(agent_id)
        info = agent_by_id.get(agent_id, {})
        number = info.get("number") or str(len(completed_agents))
        nickname = info.get("nickname") or agent_id
        anchor = f"subagent-{number}-response"
        title = f"Subagent Response: {nickname}"
        body = f"Returned via `{name}`.\n\n{completed}"
        events.append(Event("subagent", timestamp, title, body, anchor=anchor))


def parse_session(source: Path) -> tuple[dict[str, Any], list[Event], list[dict[str, str]]]:
    events: list[Event] = []
    toc: list[dict[str, str]] = []
    metadata: dict[str, Any] = {}
    calls: dict[str, dict[str, Any]] = {}
    agent_by_id: dict[str, dict[str, str]] = {}
    completed_agents: set[str] = set()
    user_count = 0
    final_count = 0
    context_count = 0
    goal_count = 0
    subagent_count = 0
    all_times: list[float] = []

    with source.open(encoding="utf-8") as handle:
        for raw in handle:
            record = json.loads(raw)
            timestamp = record.get("timestamp", "")
            timestamp_value = timestamp_seconds(timestamp)
            if timestamp_value is not None:
                all_times.append(timestamp_value)
            record_type = record.get("type")
            payload = record.get("payload") or {}

            if record_type == "session_meta":
                metadata.update(payload)
                continue

            if record_type == "compacted":
                context_count += 1
                anchor = f"context-{context_count}"
                events.append(
                    Event(
                        "system",
                        timestamp,
                        "Context Compacted",
                        "Codex summarized earlier context so the long-running thread could continue.",
                        anchor=anchor,
                    )
                )
                toc.append({"anchor": anchor, "label": f"Context compacted {context_count}", "kind": "system", "time": timestamp})
                continue

            if record_type == "event_msg":
                event_type = payload.get("type")
                if event_type == "user_message":
                    user_count += 1
                    anchor = f"user-{user_count}"
                    text = payload.get("message", "")
                    events.append(Event("user", timestamp, f"User Input {user_count}", text, anchor=anchor))
                    toc.append({"anchor": anchor, "label": milestone_label("user", user_count, text), "kind": "user", "time": timestamp})
                elif event_type == "thread_goal_updated":
                    goal_count += 1
                    goal = payload.get("goal") or {}
                    status = goal.get("status", "updated")
                    objective = goal.get("objective", "")
                    anchor = f"goal-{goal_count}"
                    events.append(
                        Event(
                            "goal",
                            timestamp,
                            f"Goal {status.title()}",
                            objective,
                            anchor=anchor,
                        )
                    )
                    toc.append({"anchor": anchor, "label": f"Goal {status}", "kind": "goal", "time": timestamp})
                elif event_type == "context_compacted":
                    context_count += 1
                    anchor = f"context-{context_count}"
                    events.append(
                        Event(
                            "system",
                            timestamp,
                            "Context Compacted",
                            "Codex compacted the live context and continued the thread.",
                            anchor=anchor,
                        )
                    )
                    toc.append({"anchor": anchor, "label": f"Context compacted {context_count}", "kind": "system", "time": timestamp})
                continue

            if record_type != "response_item":
                continue

            item_type = payload.get("type")
            if item_type == "message":
                role = payload.get("role")
                if role == "assistant":
                    text = content_text(payload.get("content"))
                    phase = payload.get("phase") or ""
                    anchor = ""
                    title = "Codex"
                    if phase == "final_answer":
                        final_count += 1
                        anchor = f"checkpoint-{final_count}"
                        title = f"Checkpoint {final_count}"
                        toc.append({"anchor": anchor, "label": checkpoint_label(final_count, text), "kind": "checkpoint", "time": timestamp})
                    events.append(Event("assistant", timestamp, title, text, phase=phase, anchor=anchor))
                continue

            if item_type == "function_call":
                call_id = payload.get("call_id")
                if call_id:
                    calls[call_id] = payload | {"timestamp": timestamp}
                continue

            if item_type == "function_call_output":
                call_id = payload.get("call_id")
                call = calls.get(call_id, {})
                name = call.get("name", "tool")
                output = payload.get("output", "")
                args = parse_args_json(call.get("arguments"))
                if name == "spawn_agent":
                    try:
                        spawn_output = json.loads(output)
                    except json.JSONDecodeError:
                        spawn_output = {}
                    agent_id = spawn_output.get("agent_id")
                    nickname = spawn_output.get("nickname") or "Subagent"
                    if agent_id and isinstance(args, dict):
                        subagent_count += 1
                        prompt = args.get("message") or args.get("prompt") or args.get("task") or ""
                        agent_by_id[agent_id] = {
                            "nickname": nickname,
                            "prompt": prompt,
                            "number": str(subagent_count),
                        }
                        anchor = f"subagent-{subagent_count}-launch"
                        title = f"Subagent Launched: {nickname}"
                        body = f"Prompt:\n\n{prompt}"
                        events.append(Event("subagent", timestamp, title, body, anchor=anchor))
                    elif output.strip():
                        subagent_count += 1
                        anchor = f"subagent-{subagent_count}-launch"
                        events.append(Event("subagent", timestamp, "Subagent Launch Attempt", output, anchor=anchor))
                elif name in {"wait_agent", "close_agent"}:
                    append_subagent_results(
                        events,
                        timestamp,
                        name,
                        args,
                        output,
                        agent_by_id,
                        completed_agents,
                    )
                continue

            if item_type == "custom_tool_call":
                continue

            if item_type == "custom_tool_call_output":
                continue

            if item_type == "web_search_call":
                continue

            if item_type == "tool_search_call":
                continue

    metadata["event_count"] = len(events)
    metadata["user_count"] = user_count
    metadata["subagent_count"] = sum(1 for event in events if event.kind == "subagent" and "Launched" in event.title)
    metadata["assistant_count"] = sum(1 for event in events if event.kind == "assistant")
    if all_times:
        metadata["runtime_seconds"] = max(all_times) - min(all_times)
    return metadata, events, toc


def event_html(event: Event, zone: ZoneInfo) -> str:
    anchor = f' id="{esc(event.anchor)}"' if event.anchor else ""
    time_label = esc(local_time(event.timestamp, zone))
    kind = esc(event.kind)
    title = esc(event.title)
    body = render_markdown(event.body)
    phase = f" {esc(event.phase)}" if event.phase else ""
    anchor_link = ""
    if event.anchor:
        anchor_link = f'<a class="anchor-link" href="#{esc(event.anchor)}">#{esc(event.anchor)}</a>'
    details = ""
    if event.details:
        details = (
            '<details class="tool-details"><summary>Details</summary>'
            f'<pre>{esc(event.details)}</pre></details>'
        )
    return f"""
<article class="event {kind}{phase}"{anchor}>
  <div class="avatar" aria-hidden="true">{avatar_for(event.kind, event.phase)}</div>
  <div class="bubble">
    <div class="event-head">
      <span class="event-title">{title} {anchor_link}</span>
      <time>{time_label}</time>
    </div>
    <div class="event-body">{body}</div>
    {details}
  </div>
</article>"""


def avatar_for(kind: str, phase: str) -> str:
    if kind == "user":
        return "U"
    if kind == "subagent":
        return "A"
    if kind == "tool":
        return ">"
    if kind == "goal":
        return "G"
    if kind == "system":
        return "S"
    if phase == "final_answer":
        return "C"
    return "C"


def render_html(metadata: dict[str, Any], events: list[Event], toc: list[dict[str, str]], zone: ZoneInfo, source: Path) -> str:
    timestamps = [event.timestamp for event in events if event.timestamp]
    start = local_time(min(timestamps), zone) if timestamps else ""
    end = local_time(max(timestamps), zone) if timestamps else ""
    generated = datetime.now(timezone.utc).astimezone(zone).strftime("%b %-d, %Y %-I:%M %p %Z")
    title = "Design WhoaThere Architecture"
    session_id = esc(metadata.get("session_id") or metadata.get("id") or "")
    cwd = esc(metadata.get("cwd", ""))
    cli = esc(metadata.get("cli_version", ""))
    runtime = duration_label(metadata.get("runtime_seconds", 0))

    toc_items = "\n".join(
        f'<a class="toc-item {esc(item["kind"])}" href="#{esc(item["anchor"])}">'
        f'<span class="toc-dot"></span><span class="toc-text">{esc(item["label"])}</span>'
        f'<time>{esc(compact_time(item["time"], zone))}</time></a>'
        for item in toc
    )
    event_markup = "\n".join(event_html(event, zone) for event in events)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} - Codex Thread Export</title>
<style>
:root {{
  color-scheme: light;
  --bg: #f7f7f4;
  --panel: #ffffff;
  --panel-2: #f0f0ec;
  --ink: #1f2328;
  --muted: #6b6f76;
  --line: #d9d9d2;
  --codex: #22252b;
  --user: #f0f7ff;
  --user-border: #9cc7f2;
  --tool: #f6f2ea;
  --goal: #eef7f0;
  --accent: #2563eb;
  --accent-2: #0f766e;
  --shadow: 0 18px 40px rgba(31, 35, 40, 0.08);
}}
* {{ box-sizing: border-box; }}
html {{ scroll-behavior: smooth; }}
body {{
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif;
}}
a {{ color: inherit; text-decoration: none; }}
.layout {{
  display: grid;
  grid-template-columns: 320px minmax(0, 1fr);
  min-height: 100vh;
}}
.sidebar {{
  position: sticky;
  top: 0;
  align-self: start;
  height: 100vh;
  overflow: auto;
  border-right: 1px solid var(--line);
  background: rgba(255, 255, 255, 0.72);
  backdrop-filter: blur(14px);
  padding: 20px 16px;
}}
.brand {{
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 18px;
}}
.mark {{
  width: 34px;
  height: 34px;
  border-radius: 8px;
  background: #111827;
  color: white;
  display: grid;
  place-items: center;
  font-weight: 700;
}}
.brand h1 {{
  font-size: 15px;
  line-height: 1.2;
  margin: 0;
  letter-spacing: 0;
}}
.brand p {{
  margin: 2px 0 0;
  color: var(--muted);
  font-size: 12px;
}}
.toc-section {{
  margin-top: 18px;
}}
.toc-heading {{
  color: var(--muted);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  margin: 18px 8px 8px;
}}
.toc-item {{
  display: grid;
  grid-template-columns: 14px 1fr auto;
  gap: 8px;
  align-items: start;
  padding: 8px;
  border-radius: 8px;
  color: #3c4148;
  min-height: 34px;
}}
.toc-item:hover, .toc-item.active {{
  background: var(--panel-2);
}}
.toc-item.user {{
  color: #123e72;
  font-weight: 650;
}}
.toc-item.checkpoint {{
  color: #245043;
}}
.toc-dot {{
  width: 7px;
  height: 7px;
  margin-top: 7px;
  border-radius: 50%;
  background: #a8adb5;
}}
.toc-item.user .toc-dot {{ background: var(--accent); }}
.toc-item.checkpoint .toc-dot {{ background: var(--accent-2); }}
.toc-item.goal .toc-dot {{ background: #7c3aed; }}
.toc-text {{
  overflow: hidden;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
}}
.toc-item time {{
  color: var(--muted);
  font-size: 11px;
  white-space: nowrap;
}}
.main {{
  min-width: 0;
}}
.topbar {{
  position: sticky;
  top: 0;
  z-index: 5;
  border-bottom: 1px solid var(--line);
  background: rgba(247, 247, 244, 0.86);
  backdrop-filter: blur(14px);
}}
.topbar-inner {{
  max-width: 1040px;
  margin: 0 auto;
  padding: 16px 24px;
  display: flex;
  gap: 14px;
  align-items: center;
  justify-content: space-between;
}}
.title h2 {{
  margin: 0;
  font-size: 18px;
  line-height: 1.25;
}}
.title p {{
  margin: 3px 0 0;
  color: var(--muted);
  font-size: 12px;
}}
.controls {{
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
  justify-content: flex-end;
}}
.chip, button {{
  border: 1px solid var(--line);
  background: var(--panel);
  border-radius: 8px;
  padding: 7px 10px;
  color: #2d333b;
  font: inherit;
  font-size: 12px;
}}
button {{ cursor: pointer; }}
button.active {{ border-color: #8bb8f6; background: #eef6ff; }}
.content {{
  max-width: 1040px;
  margin: 0 auto;
  padding: 26px 24px 70px;
}}
.hero {{
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  box-shadow: var(--shadow);
  padding: 22px;
  margin-bottom: 24px;
}}
.hero h3 {{
  margin: 0 0 8px;
  font-size: 24px;
  letter-spacing: 0;
}}
.hero p {{
  margin: 0;
  color: var(--muted);
  max-width: 840px;
}}
.stats {{
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 10px;
  margin-top: 18px;
}}
.stat {{
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px;
  background: #fbfbf8;
}}
.stat strong {{
  display: block;
  font-size: 18px;
}}
.stat span {{
  color: var(--muted);
  font-size: 12px;
}}
.meta {{
  display: grid;
  gap: 6px;
  margin-top: 14px;
  color: var(--muted);
  font-size: 12px;
}}
.timeline {{
  display: grid;
  gap: 12px;
}}
.event {{
  display: grid;
  grid-template-columns: 36px minmax(0, 1fr);
  gap: 12px;
  scroll-margin-top: 86px;
}}
.event.user {{
  grid-template-columns: minmax(0, 1fr) 36px;
}}
.event.user .avatar {{ grid-column: 2; }}
.event.user .bubble {{ grid-column: 1; grid-row: 1; justify-self: end; }}
.avatar {{
  width: 34px;
  height: 34px;
  border-radius: 8px;
  display: grid;
  place-items: center;
  color: white;
  background: var(--codex);
  font-size: 13px;
  font-weight: 700;
}}
.event.user .avatar {{ background: var(--accent); }}
.event.tool .avatar {{ background: #8a6f3d; }}
.event.subagent .avatar {{ background: #7c3aed; }}
.event.goal .avatar {{ background: #6d28d9; }}
.event.system .avatar {{ background: #6b7280; }}
.bubble {{
  width: min(780px, 100%);
  border: 1px solid var(--line);
  background: var(--panel);
  border-radius: 8px;
  padding: 13px 14px;
}}
.event.user .bubble {{
  background: var(--user);
  border-color: var(--user-border);
}}
.event.tool .bubble {{
  background: var(--tool);
  color: #4c3f2d;
}}
.event.subagent .bubble {{
  background: #f5f0ff;
  border-color: #d3c2ff;
}}
.event.goal .bubble {{
  background: var(--goal);
}}
.event.system .bubble {{
  background: #f3f4f6;
}}
.event.final_answer .bubble {{
  border-color: #b6d4c9;
  background: #fbfffc;
}}
.event-head {{
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: baseline;
  margin-bottom: 7px;
}}
.event-title {{
  font-weight: 700;
}}
.anchor-link {{
  margin-left: 6px;
  color: var(--muted);
  font-weight: 600;
  font-size: 12px;
}}
.anchor-link:hover {{
  color: var(--accent);
  text-decoration: underline;
}}
.event-head time {{
  color: var(--muted);
  font-size: 12px;
  white-space: nowrap;
}}
.event-body {{
  overflow-wrap: anywhere;
}}
.event-body p {{
  margin: 0 0 10px;
}}
.event-body p:last-child {{
  margin-bottom: 0;
}}
.event-body h3,
.event-body h4,
.event-body h5,
.event-body h6 {{
  margin: 14px 0 8px;
  line-height: 1.25;
}}
.event-body ul,
.event-body ol {{
  margin: 8px 0 10px 22px;
  padding: 0;
}}
.event-body li {{
  margin: 4px 0;
}}
.event-body blockquote {{
  margin: 8px 0;
  padding-left: 12px;
  border-left: 3px solid var(--line);
  color: var(--muted);
}}
.event-body code {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.92em;
  background: #eef0f3;
  border: 1px solid #dde1e6;
  border-radius: 5px;
  padding: 1px 4px;
}}
.event-body pre code {{
  background: transparent;
  border: 0;
  padding: 0;
  color: inherit;
}}
.event-body a {{
  color: #1d4ed8;
  text-decoration: underline;
  text-underline-offset: 2px;
}}
.tool-details {{
  margin-top: 10px;
}}
.tool-details summary {{
  cursor: pointer;
  color: #6b5630;
  font-weight: 650;
}}
pre {{
  max-height: 360px;
  overflow: auto;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: #111827;
  color: #f9fafb;
  padding: 12px;
  font-size: 12px;
  line-height: 1.45;
  white-space: pre-wrap;
}}
@media (max-width: 900px) {{
  .layout {{ grid-template-columns: 1fr; }}
  .sidebar {{
    position: relative;
    height: auto;
    max-height: 45vh;
    border-right: 0;
    border-bottom: 1px solid var(--line);
  }}
  .topbar {{ position: relative; }}
  .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .event.user, .event {{ grid-template-columns: 32px minmax(0, 1fr); }}
  .event.user .avatar {{ grid-column: 1; }}
  .event.user .bubble {{ grid-column: 2; justify-self: stretch; }}
}}
</style>
</head>
<body>
<div class="layout">
  <aside class="sidebar">
    <div class="brand">
      <div class="mark">C</div>
      <div>
        <h1>Codex Thread Export</h1>
        <p>Redacted local HTML transcript</p>
      </div>
    </div>
    <div class="toc-section">
      <div class="toc-heading">Milestones</div>
      <a class="toc-item system" href="#overview"><span class="toc-dot"></span><span class="toc-text">Overview</span><time></time></a>
      {toc_items}
    </div>
  </aside>
  <main class="main">
    <header class="topbar">
      <div class="topbar-inner">
        <div class="title">
          <h2>{esc(title)}</h2>
          <p>{esc(start)} to {esc(end)}</p>
        </div>
        <div class="controls">
          <span class="chip">Redacted for sharing</span>
        </div>
      </div>
    </header>
    <section class="content">
      <section class="hero" id="overview">
        <h3>WhoaThere Architecture Run</h3>
        <p>This export captures the active Codex thread as a readable conversation: user milestones are pinned in the left navigation, assistant progress and subagent memos appear in chronological order, and generic command/tool logs are omitted. Redacted for sharing means secret-shaped values and local credential material are removed from the export.</p>
        <div class="stats">
          <div class="stat"><strong>{esc(runtime)}</strong><span>Thread runtime</span></div>
          <div class="stat"><strong>{metadata.get("user_count", 0)}</strong><span>User inputs</span></div>
          <div class="stat"><strong>{metadata.get("assistant_count", 0)}</strong><span>Codex messages</span></div>
          <div class="stat"><strong>{metadata.get("subagent_count", 0)}</strong><span>Subagents launched</span></div>
          <div class="stat"><strong>{metadata.get("event_count", 0)}</strong><span>Total events</span></div>
        </div>
        <div class="meta">
          <div>Session: <code>{session_id}</code></div>
          <div>Workspace: <code>{cwd}</code></div>
          <div>Codex CLI: <code>{cli}</code></div>
          <div>Source JSONL: <code>{esc(str(source).replace("/Users/jdc", "~"))}</code></div>
          <div>Generated: {esc(generated)}</div>
        </div>
      </section>
      <section class="timeline">
        {event_markup}
      </section>
    </section>
  </main>
</div>
<script>
const links = Array.from(document.querySelectorAll('.toc-item[href^="#"]'));
const targets = links.map(link => document.querySelector(link.getAttribute('href'))).filter(Boolean);
const byId = new Map(links.map(link => [link.getAttribute('href').slice(1), link]));
const observer = new IntersectionObserver(entries => {{
  entries.forEach(entry => {{
    if (!entry.isIntersecting) return;
    links.forEach(link => link.classList.remove('active'));
    const active = byId.get(entry.target.id);
    if (active) active.classList.add('active');
  }});
}}, {{ rootMargin: '-20% 0px -70% 0px', threshold: 0 }});
targets.forEach(target => observer.observe(target));
</script>
</body>
</html>
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE_DEFAULT)
    parser.add_argument("--output", type=Path, default=OUTPUT_DEFAULT)
    parser.add_argument("--timezone", default="America/New_York")
    args = parser.parse_args()

    zone = ZoneInfo(args.timezone)
    metadata, events, toc = parse_session(args.source)
    html_text = render_html(metadata, events, toc, zone, args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html_text, encoding="utf-8")
    print(args.output)
    print(
        f"events={len(events)} user_inputs={metadata.get('user_count')} "
        f"subagents={metadata.get('subagent_count')} runtime={duration_label(metadata.get('runtime_seconds', 0))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
