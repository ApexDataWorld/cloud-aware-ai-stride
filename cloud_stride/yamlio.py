from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any


def _strip_comments(line: str) -> str:
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "None", "~"}:
        return None
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return ast.literal_eval(value)
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        parts = [part.strip() for part in inner.split(",")]
        parsed_items = []
        for part in parts:
            if part.startswith(("'", '"', "{", "[")) or part in {"true", "false", "True", "False", "null", "None", "~"}:
                parsed_items.append(_parse_scalar(part))
                continue
            try:
                parsed_items.append(_parse_scalar(part))
            except Exception:
                parsed_items.append(part)
        return parsed_items
    if value.startswith("{") and value.endswith("}"):
        normalized = value.replace("true", "True").replace("false", "False").replace("null", "None")
        normalized = re.sub(r'([{,]\s*)([A-Za-z_][A-Za-z0-9_-]*)(\s*:)', r'\1"\2"\3', normalized)
        return ast.literal_eval(normalized)
    try:
        if "." in value:
            return float(value)
        return int(value)
    except ValueError:
        return value


def _parse_block(lines: list[tuple[int, str]], start: int, indent: int) -> tuple[Any, int]:
    if start >= len(lines):
        return {}, start

    current_indent, content = lines[start]
    if current_indent < indent:
        return {}, start

    if content.startswith("- "):
        items: list[Any] = []
        index = start
        while index < len(lines):
            line_indent, line = lines[index]
            if line_indent < indent or not line.startswith("- "):
                break
            item_content = line[2:].strip()
            if not item_content:
                nested, next_index = _parse_block(lines, index + 1, line_indent + 2)
                items.append(nested)
                index = next_index
                continue
            if ": " in item_content or item_content.endswith(":"):
                pseudo_line = (line_indent + 2, item_content)
                nested, next_index = _parse_block([pseudo_line, *lines[index + 1 :]], 0, line_indent + 2)
                items.append(nested)
                index = index + next_index
                continue
            items.append(_parse_scalar(item_content))
            index += 1
        return items, index

    mapping: dict[str, Any] = {}
    index = start
    while index < len(lines):
        line_indent, line = lines[index]
        if line_indent < indent:
            break
        if line_indent > indent:
            raise ValueError(f"Unexpected indentation for line: {line}")
        if ":" not in line:
            raise ValueError(f"Expected mapping entry, got: {line}")
        key, raw_value = line.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        if raw_value == "|":
            block_lines: list[str] = []
            index += 1
            while index < len(lines) and lines[index][0] > line_indent:
                block_lines.append(lines[index][1].strip())
                index += 1
            mapping[key] = "\n".join(block_lines)
            continue
        if raw_value == ">":
            block_lines = []
            index += 1
            while index < len(lines) and lines[index][0] > line_indent:
                block_lines.append(lines[index][1].strip())
                index += 1
            mapping[key] = " ".join(block_lines)
            continue
        if raw_value == "":
            nested, next_index = _parse_block(lines, index + 1, line_indent + 2)
            mapping[key] = nested
            index = next_index
            continue
        mapping[key] = _parse_scalar(raw_value)
        index += 1
    return mapping, index


def load_yaml(path: str | Path) -> Any:
    source = Path(path).read_text(encoding="utf-8").splitlines()
    lines: list[tuple[int, str]] = []
    for raw_line in source:
        cleaned = _strip_comments(raw_line).rstrip()
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        lines.append((indent, cleaned.strip()))
    parsed, _ = _parse_block(lines, 0, 0)
    return parsed


def dump_yaml(data: Any, indent: int = 0) -> str:
    prefix = " " * indent
    if isinstance(data, dict):
        lines: list[str] = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(dump_yaml(value, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {value}")
        return "\n".join(lines)
    if isinstance(data, list):
        lines = []
        for value in data:
            if isinstance(value, (dict, list)):
                lines.append(f"{prefix}-")
                lines.append(dump_yaml(value, indent + 2))
            else:
                lines.append(f"{prefix}- {value}")
        return "\n".join(lines)
    return f"{prefix}{data}"
