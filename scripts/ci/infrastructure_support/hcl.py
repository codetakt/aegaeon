"""Strict HCL-shaped expression and environment parsing."""

from __future__ import annotations

import re

from infrastructure_support.common import require

TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|/\*.*?\*/|//[^\n]*|\#[^\n]*|[{}]', re.DOTALL)

ENV_IDENTIFIER = r"[A-Z][A-Z0-9_]*"

STRING = r'"(?:[^"\\]|\\.)*"'

EXPRESSION_TOKEN = re.compile(STRING + r"|[\[\]{}()\n]")

REFERENCE = r"(?:var|local|data|aws_[a-z0-9_]+)(?:\.[A-Za-z_][A-Za-z0-9_]*)+"

VALUE = re.compile(
    rf"(?:{STRING}|{REFERENCE}|true|false|[0-9]+|{REFERENCE}\s*\?\s*{STRING}\s*:\s*{STRING})"
)


def uncomment(text: str) -> str:
    return TOKEN.sub(lambda m: m[0] if m[0][0] in '"{}' else " ", text)


def block(text: str, header: str) -> str:
    """Extract one explicit HCL block, respecting strings/comments and nesting."""
    text = uncomment(text)
    matches = list(re.finditer(r"(?m)^\s*" + re.escape(header) + r"\s*\{", text))
    require(len(matches) == 1, f"Expected exactly one {header} block")
    start = matches[0].end()
    depth = 1
    for token in TOKEN.finditer(text, start):
        if token[0] == "{":
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                return text[start : token.start()]
    raise ValueError(f"Unclosed {header} block")


def top_level(text: str) -> str:
    text = uncomment(text)
    result = []
    depth = 0
    start = 0
    for token in TOKEN.finditer(text):
        if token[0] == "{":
            if depth == 0:
                result.append(text[start : token.start()])
            depth += 1
        elif token[0] == "}":
            depth -= 1
            if depth == 0:
                result.append(" {} ")
                start = token.end()
    require(depth == 0, "Unbalanced HCL block")
    result.append(text[start:])
    return "".join(result)


def assignment(text: str, name: str) -> str:
    matches = re.findall(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*([^\n]+)", top_level(text))
    require(len(matches) == 1, f"Expected one explicit {name} assignment")
    return str(matches[0].strip())


def strict_matches(pattern: str, text: str, label: str) -> list[re.Match[str]]:
    matches = list(re.finditer(pattern, text, re.DOTALL))
    require(
        bool(matches) and not re.sub(pattern, "", text, flags=re.DOTALL).strip(),
        f"Malformed {label}",
    )
    return matches


def quoted_names(text: str) -> list[str]:
    matches = strict_matches(rf'\s*"({ENV_IDENTIFIER})"\s*,?\s*', text, "environment-name list")
    names = [match[1] for match in matches]
    require(len(names) == len(set(names)), "Duplicate environment name")
    return names


def top_level_position(text: str, position: int) -> bool:
    stack: list[str] = []
    pairs = {"]": "[", "}": "{", ")": "("}
    for token in EXPRESSION_TOKEN.finditer(text, 0, position):
        if token[0] in ("[", "{", "("):
            stack.append(token[0])
        elif token[0] in pairs:
            require(bool(stack) and stack.pop() == pairs[token[0]], "Unbalanced input scope")
    return not stack


def expression(text: str, name: str) -> str:
    text = uncomment(text)
    matches = [
        match
        for match in re.finditer(r"(?m)^\s*" + re.escape(name) + r"\s*=\s*", text)
        if top_level_position(text, match.end())
    ]
    require(len(matches) == 1, f"Expected one explicit {name} expression")
    start = matches[0].end()
    stack: list[str] = []
    pairs = {"]": "[", "}": "{", ")": "("}
    for token in EXPRESSION_TOKEN.finditer(text, start):
        value = token[0]
        if value in ("[", "{", "("):
            stack.append(value)
        elif value in pairs:
            require(bool(stack) and stack.pop() == pairs[value], "Unbalanced expression")
        elif value == "\n" and not stack:
            return text[start : token.start()].strip().rstrip(",").strip()
    require(not stack, "Unclosed expression")
    return text[start:].strip().rstrip(",").strip()


def environment_objects(text: str, attribute: str) -> dict[str, str]:
    require(attribute in {"value", "valueFrom"}, "Unknown ECS environment attribute")
    require(text.startswith("[") and text.endswith("]"), "Expected literal environment array")
    if not text[1:-1].strip():
        return {}
    objects = strict_matches(
        rf'\s*\{{\s*name\s*=\s*"({ENV_IDENTIFIER})"\s*,?\s*{attribute}\s*=\s*((?:{STRING}|[^{{}}"])+?)\s*,?\s*\}}\s*,?\s*',
        text[1:-1],
        f"environment assignments requiring {attribute}",
    )
    result = {}
    for item in objects:
        require(item[1] not in result, f"Duplicate environment assignment: {item[1]}")
        require(
            VALUE.fullmatch(item[2].strip()) is not None, f"Unsupported value expression: {item[1]}"
        )
        result[item[1]] = item[2].strip()
    return result


def combined(*groups: dict[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for group in groups:
        require(not (result.keys() & group.keys()), "Duplicate process environment assignment")
        result.update(group)
    return result


def heredoc_environment(text: str, name: str) -> dict[str, str]:
    matches = re.findall(
        r"(?m)^cat >/etc/aegaeon/" + re.escape(name) + r"\.env <<EOF\n(.*?)\nEOF$", text, re.DOTALL
    )
    require(len(matches) == 1, f"Missing or duplicate {name} environment heredoc")
    result = {}
    for line in matches[0].splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = re.fullmatch(rf"({ENV_IDENTIFIER})=(.*)", line)
        require(match is not None, f"Malformed {name} environment assignment")
        if match is None:
            raise ValueError("Missing environment assignment")
        require(match[1] not in result, f"Duplicate environment assignment: {match[1]}")
        result[match[1]] = match[2]
    return result


def compact_expression(text: str) -> str:
    return re.sub(
        r'"(?:[^"\\]|\\.)*"|\s+', lambda match: match[0] if match[0].startswith('"') else "", text
    )
