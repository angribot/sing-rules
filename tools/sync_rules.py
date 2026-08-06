from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RULE_SET_VERSION = 3
DEFAULT_MANIFEST_NAME = ".generated-files.txt"
IGNORED_SOURCE_FILES = {"boost.lsr"}
NAME_OVERRIDES = {
    "YouTube": "youtube",
    "TikTok": "tiktok",
    "iCloud": "icloud",
}
SIMPLE_RULE_TYPES = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "PROCESS-NAME": "process_name",
}
IGNORED_RULE_TYPES = {
    "IP-ASN",
}
UNSUPPORTED_RULE_TYPES = {
    "URL-REGEX",
}
RULE_TYPE_ORDER = {
    "DOMAIN": 10,
    "DOMAIN-SUFFIX": 20,
    "DOMAIN-KEYWORD": 30,
    "DOMAIN-REGEX": 40,
    "IP-CIDR": 50,
    "IP-CIDR6": 50,
    "PROCESS-NAME": 60,
    "AND": 70,
    "OR": 80,
    "NOT": 90,
}
SIMPLE_FIELD_ORDER = {
    "domain": 10,
    "domain_suffix": 20,
    "domain_keyword": 30,
    "domain_regex": 40,
    "ip_cidr": 50,
    "process_name": 60,
}
# Fields in each group are ORed by sing-box within one default headless rule.
SIMPLE_FIELD_OR_GROUPS = (
    ("domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr"),
)


class ConversionError(ValueError):
    pass


@dataclass
class GenerationResult:
    generated_files: list[Path]
    unsupported_entries: list[str]


def strip_inline_comment(line: str) -> str:
    comment_index = line.find("//")
    if comment_index != -1:
        return line[:comment_index].strip()
    return line.strip()


def is_wrapped_by_parentheses(text: str) -> bool:
    if len(text) < 2 or text[0] != "(" or text[-1] != ")":
        return False
    depth = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0 and index != len(text) - 1:
                return False
        if depth < 0:
            return False
    return depth == 0


def unwrap_parentheses(text: str) -> str:
    current = text.strip()
    while is_wrapped_by_parentheses(current):
        current = current[1:-1].strip()
    return current


def split_top_level(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise ConversionError(f"Unbalanced parentheses in expression: {text}")
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    if depth != 0:
        raise ConversionError(f"Unbalanced parentheses in expression: {text}")
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def normalize_value(rule_type: str, value: str) -> str:
    return value


def make_simple_rule(rule_type: str, value: str) -> dict[str, Any]:
    field = SIMPLE_RULE_TYPES[rule_type]
    return {field: [normalize_value(rule_type, value)]}


def parse_expression(expression: str) -> tuple[dict[str, Any] | None, str | None]:
    expression = unwrap_parentheses(expression.strip())
    if not expression:
        return None, None

    if expression.startswith("AND,"):
        return parse_logical_expression("and", expression[4:].strip())
    if expression.startswith("OR,"):
        return parse_logical_expression("or", expression[3:].strip())
    if expression.startswith("NOT,"):
        return parse_logical_expression("not", expression[4:].strip())

    parts = [part.strip() for part in expression.split(",")]
    if len(parts) < 2:
        raise ConversionError(f"Malformed rule expression: {expression}")

    rule_type = parts[0].upper()
    value = parts[1]

    if rule_type in SIMPLE_RULE_TYPES:
        return make_simple_rule(rule_type, value), None
    if rule_type in IGNORED_RULE_TYPES:
        return None, None
    if rule_type in UNSUPPORTED_RULE_TYPES:
        return None, f"{rule_type},{value}"

    raise ConversionError(f"Unsupported rule type: {rule_type}")


def parse_logical_expression(mode: str, body: str) -> tuple[dict[str, Any], None]:
    stripped = body.strip()
    if not is_wrapped_by_parentheses(stripped):
        raise ConversionError(f"Logical rule must wrap child rules in parentheses: {body}")

    children = split_top_level(stripped[1:-1].strip())
    if mode == "not":
        if len(children) != 1:
            raise ConversionError(f"Logical NOT rule requires exactly one child rule: {body}")
    elif len(children) < 2:
        raise ConversionError(f"Logical rule requires at least two child rules: {body}")

    rules: list[dict[str, Any]] = []
    for child in children:
        child_rule, unsupported = parse_expression(child)
        if unsupported is not None:
            raise ConversionError(f"Unsupported rule inside logical expression: {unsupported}")
        if child_rule is None:
            raise ConversionError(f"Empty child rule in logical expression: {body}")
        rules.append(child_rule)

    if mode == "not":
        return toggle_rule_invert(rules[0]), None
    return {"type": "logical", "mode": mode, "rules": rules}, None


def toggle_rule_invert(rule: dict[str, Any]) -> dict[str, Any]:
    inverted_rule = dict(rule)
    if inverted_rule.get("invert"):
        del inverted_rule["invert"]
    else:
        inverted_rule["invert"] = True
    return inverted_rule


def is_logical_rule(rule: dict[str, Any]) -> bool:
    return rule.get("type") == "logical"


def is_mergeable_default_rule(rule: dict[str, Any]) -> bool:
    return not is_logical_rule(rule) and "invert" not in rule and len(rule) == 1


def string_sort_key(value: str) -> str:
    return value.casefold()


def keyword_sort_key(value: str) -> str:
    return value.casefold()


def ip_cidr_sort_key(value: str) -> tuple[int, int, int, str]:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        address = ipaddress.ip_address(value)
        max_prefix = 32 if address.version == 4 else 128
        network = ipaddress.ip_network(f"{value}/{max_prefix}", strict=False)
    return (network.version, int(network.network_address), network.prefixlen, value)


def deduplicate_values(values: list[Any]) -> list[Any]:
    return list(dict.fromkeys(values))


def sort_grouped_values(field: str, values: list[Any]) -> list[Any]:
    unique_values = deduplicate_values(values)
    if field in {"domain", "domain_suffix"}:
        return sorted(unique_values, key=string_sort_key)
    if field in {"domain_keyword", "domain_regex", "process_name"}:
        return sorted(unique_values, key=keyword_sort_key)
    if field == "ip_cidr":
        return sorted(unique_values, key=ip_cidr_sort_key)
    return unique_values


def normalize_simple_rule(rule: dict[str, Any]) -> dict[str, Any]:
    field = next(field for field in rule if field != "invert")
    normalized_rule = {field: sort_grouped_values(field, rule[field])}
    if rule.get("invert"):
        normalized_rule["invert"] = True
    return normalized_rule


def aggregate_simple_rules(mergeable_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped_values: dict[str, list[Any]] = {}
    for rule in mergeable_rules:
        field, values = next(iter(rule.items()))
        grouped_values.setdefault(field, []).extend(values)

    aggregated_rules: list[dict[str, Any]] = []
    grouped_fields: set[str] = set()
    for field_group in SIMPLE_FIELD_OR_GROUPS:
        compound_rule = {
            field: sort_grouped_values(field, grouped_values[field])
            for field in field_group
            if field in grouped_values
        }
        if compound_rule:
            aggregated_rules.append(compound_rule)
            grouped_fields.update(compound_rule)

    for field in sorted(
        grouped_values.keys() - grouped_fields,
        key=lambda item: (SIMPLE_FIELD_ORDER.get(item, 999), item),
    ):
        aggregated_rules.append({field: sort_grouped_values(field, grouped_values[field])})

    return aggregated_rules


def serialize_rule(rule: dict[str, Any]) -> str:
    return json.dumps(rule, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def deduplicate_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique_rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    for rule in rules:
        serialized = serialize_rule(rule)
        if serialized in seen:
            continue
        seen.add(serialized)
        unique_rules.append(rule)
    return unique_rules


def rule_sort_key(rule: dict[str, Any]) -> tuple[int, str]:
    if rule.get("invert"):
        order = RULE_TYPE_ORDER["NOT"]
    elif is_logical_rule(rule):
        order = RULE_TYPE_ORDER.get(rule["mode"].upper(), 999)
    else:
        field = next(field for field in rule if field != "invert")
        order = SIMPLE_FIELD_ORDER.get(field, 999)
    return (order, serialize_rule(rule))


def normalize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    if is_logical_rule(rule):
        return normalize_logical_rule(rule)
    return normalize_simple_rule(rule)


def normalize_logical_rule(rule: dict[str, Any]) -> dict[str, Any]:
    mode = rule["mode"]
    normalized_children = [normalize_rule(child) for child in rule["rules"]]

    if mode == "or":
        mergeable_children = [child for child in normalized_children if is_mergeable_default_rule(child)]
        remaining_children = [child for child in normalized_children if not is_mergeable_default_rule(child)]
        children = aggregate_simple_rules(mergeable_children) + sorted(
            deduplicate_rules(remaining_children), key=rule_sort_key
        )
    else:
        children = sorted(deduplicate_rules(normalized_children), key=rule_sort_key)

    normalized_rule: dict[str, Any] = {"type": "logical", "mode": mode, "rules": children}
    if rule.get("invert"):
        normalized_rule["invert"] = True
    return normalized_rule


def normalize_top_level_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_rules = [normalize_rule(rule) for rule in rules]
    mergeable_rules = [rule for rule in normalized_rules if is_mergeable_default_rule(rule)]
    remaining_rules = [rule for rule in normalized_rules if not is_mergeable_default_rule(rule)]
    return aggregate_simple_rules(mergeable_rules) + sorted(deduplicate_rules(remaining_rules), key=rule_sort_key)


def extract_rule_type(expression: str) -> str:
    parts = expression.split(",", 1)
    if not parts or not parts[0].strip():
        raise ConversionError(f"Malformed rule expression: {expression}")
    return parts[0].strip().upper()


def sort_rule_entry(entry: tuple[str, int, str]) -> tuple[int, str, int]:
    rule_type, line_number, _ = entry
    return (RULE_TYPE_ORDER.get(rule_type, 999), rule_type, line_number)


def convert_lsr_content(content: str, source_name: str) -> tuple[dict[str, Any], list[str]]:
    parsed_rules: list[dict[str, Any]] = []
    unsupported_entries: list[str] = []

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#") or stripped_line.startswith(";"):
            continue

        normalized_line = strip_inline_comment(raw_line)
        if not normalized_line:
            continue

        try:
            rule, unsupported = parse_expression(normalized_line)
        except ConversionError as exc:
            raise ConversionError(f"{source_name}:{line_number}: {exc}") from exc

        if rule is not None:
            parsed_rules.append(rule)
        if unsupported is not None:
            unsupported_entries.append(f"{source_name}:{line_number}: {unsupported}")

    return {"version": RULE_SET_VERSION, "rules": normalize_top_level_rules(parsed_rules)}, unsupported_entries


def load_previous_manifest(output_dir: Path, manifest_name: str) -> list[Path]:
    manifest_path = output_dir / manifest_name
    if not manifest_path.exists():
        return []
    entries = [line.strip() for line in manifest_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [output_dir / entry for entry in entries]


def write_manifest(output_dir: Path, manifest_name: str, generated_files: list[Path]) -> None:
    manifest_path = output_dir / manifest_name
    relative_paths = [path.relative_to(output_dir).as_posix() for path in generated_files]
    manifest_path.write_text("\n".join(relative_paths) + ("\n" if relative_paths else ""), encoding="utf-8")


def to_snake_case(name: str) -> str:
    overridden = NAME_OVERRIDES.get(name)
    if overridden is not None:
        return overridden

    first_pass = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    second_pass = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first_pass)
    return second_pass.replace("-", "_").lower()


def compile_srs(sing_box_binary: Path, json_path: Path, srs_path: Path) -> None:
    command = [
        str(sing_box_binary),
        "rule-set",
        "compile",
        "--output",
        str(srs_path),
        str(json_path),
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"Failed to compile {json_path.name} to {srs_path.name}:\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )


def generate_rule_artifacts(
    source_dir: Path,
    output_dir: Path,
    sing_box_binary: Path,
    manifest_name: str = DEFAULT_MANIFEST_NAME,
    clean: bool = False,
) -> GenerationResult:
    source_dir = source_dir.resolve()
    output_dir = output_dir.resolve()
    sing_box_binary = sing_box_binary.resolve()

    if clean:
        for path in load_previous_manifest(output_dir, manifest_name):
            if path.exists():
                path.unlink()

    generated_files: list[Path] = []
    unsupported_entries: list[str] = []

    for lsr_path in sorted(source_dir.glob("*.lsr")):
        if lsr_path.name in IGNORED_SOURCE_FILES:
            continue

        rule_set, unsupported = convert_lsr_content(
            lsr_path.read_text(encoding="utf-8"),
            source_name=lsr_path.name,
        )
        unsupported_entries.extend(unsupported)

        stem = to_snake_case(lsr_path.stem)
        json_path = output_dir / f"{stem}.json"
        srs_path = output_dir / f"{stem}.srs"

        json_path.write_text(json.dumps(rule_set, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
        compile_srs(sing_box_binary, json_path, srs_path)

        generated_files.extend([json_path, srs_path])

    write_manifest(output_dir, manifest_name, generated_files)
    return GenerationResult(generated_files=generated_files, unsupported_entries=unsupported_entries)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert .lsr rules into sing-box JSON and SRS artifacts.")
    parser.add_argument("--source-dir", required=True, type=Path, help="Directory containing upstream .lsr files")
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory to write .json and .srs artifacts")
    parser.add_argument("--sing-box", required=True, type=Path, help="Path to the sing-box binary")
    parser.add_argument("--manifest-name", default=DEFAULT_MANIFEST_NAME, help="Manifest file used to track generated artifacts")
    parser.add_argument("--clean", action="store_true", help="Remove previously generated artifacts before writing new ones")
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()

    result = generate_rule_artifacts(
        source_dir=args.source_dir,
        output_dir=args.output_dir,
        sing_box_binary=args.sing_box,
        manifest_name=args.manifest_name,
        clean=args.clean,
    )

    print(f"Generated {len(result.generated_files)} artifacts from {args.source_dir}")
    if result.unsupported_entries:
        print("Skipped unsupported entries:")
        for entry in result.unsupported_entries:
            print(f"- {entry}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
