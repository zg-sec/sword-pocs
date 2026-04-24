#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 基于ScanSword项目，校验模板名称是否符合规则

import argparse
import hashlib
import os
import re
import sys
import unicodedata
from collections import Counter, defaultdict


CVE_RE = re.compile(r"^CVE-\d{4}-[A-Za-z0-9-]+$")
CANONICAL_CVE_RE = re.compile(r"(?i)^CVE[-_ ]?(\d{4})[-_ ]?(\d{4,})$")


def ascii_text(text: str) -> str:
    text = unicodedata.normalize("NFKD", text)
    return text.encode("ascii", "ignore").decode("ascii")


def kebab(text: str) -> str:
    text = ascii_text(text or "").strip()
    text = text.replace("&", " and ")
    for ch in ['"', "'", "`"]:
        text = text.replace(ch, "")
    text = text.replace("_", "-")
    text = re.sub(r"[^A-Za-z0-9-]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    return text.lower()


def file_stem(name: str) -> str:
    return re.sub(r"\.ya?ml$", "", name, flags=re.I)


def canonical_cve(raw: str) -> str:
    match = CANONICAL_CVE_RE.match((raw or "").strip())
    if not match:
        return ""
    return f"CVE-{match.group(1)}-{match.group(2)}"


def extract_meta(path: str) -> dict:
    text = open(path, "r", encoding="utf-8", errors="replace").read().replace("\r\n", "\n")
    lines = text.splitlines()
    meta = {"id": "", "name": "", "cve": "", "text": text}
    in_classification = False
    idx = 0

    while idx < len(lines):
        line = lines[idx]
        stripped = line.strip()

        if line.startswith("id:") and not meta["id"]:
            meta["id"] = line.split(":", 1)[1].strip()

        if line.startswith("  name:") and not meta["name"]:
            value = line.split(":", 1)[1].strip()
            if value in (">", "|"):
                parts = []
                j = idx + 1
                while j < len(lines):
                    nxt = lines[j]
                    if nxt.startswith("    ") or not nxt.strip():
                        if nxt.strip():
                            parts.append(nxt.strip())
                        j += 1
                    else:
                        break
                meta["name"] = " ".join(parts)
            else:
                meta["name"] = value.strip('"')

        if stripped == "classification:":
            in_classification = True
        elif line and not line.startswith("    "):
            in_classification = False

        if in_classification and stripped.startswith("cve-id:") and not meta["cve"]:
            meta["cve"] = stripped.split(":", 1)[1].strip()

        idx += 1

    return meta


def normalize_exact(text: str) -> str:
    return re.sub(r"(?m)^id:\s*.*$", "id: __ID__", text, count=1)


def normalize_detection(text: str) -> str:
    lines = text.splitlines(True)
    output = []
    idx = 0
    skipping_info = False
    info_indent = 0

    while idx < len(lines):
        line = lines[idx]
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)

        if idx == 0 and stripped.startswith("id:"):
            idx += 1
            continue

        if not skipping_info and stripped == "info:\n":
            skipping_info = True
            info_indent = indent
            idx += 1
            continue

        if skipping_info:
            if stripped.strip() == "":
                idx += 1
                continue
            if indent > info_indent:
                idx += 1
                continue
            skipping_info = False

        output.append(line)
        idx += 1

    return "".join(output).strip() + "\n"


def validate_names(root: str, files: list[str]) -> list[tuple[str, str]]:
    errors = []
    for filename in files:
        path = os.path.join(root, filename)
        stem = file_stem(filename)
        meta = extract_meta(path)

        if " " in filename:
            errors.append((filename, "文件名包含空格"))
        if "_" in filename:
            errors.append((filename, "文件名包含下划线"))
        if stem != meta["id"]:
            errors.append((filename, f"文件名 stem 与 id 不一致: stem={stem}, id={meta['id']}"))

        if stem.startswith("CVE-"):
            if not CVE_RE.fullmatch(stem):
                errors.append((filename, "CVE 文件名不符合 `CVE-YYYY-...` 规范"))
        else:
            if stem != kebab(stem):
                errors.append((filename, "非 CVE 文件名不是小写 kebab-case"))

        if meta["cve"]:
            normalized = canonical_cve(meta["cve"])
            if normalized and stem == normalized.lower():
                errors.append((filename, "存在合法 cve-id，但文件名错误地使用了小写 cve 形式"))

    return errors


def find_temp_files(files: list[str]) -> list[str]:
    return [f for f in files if f.startswith(".rename-tmp-") or f.startswith(".write-tmp-")]


def find_exact_duplicates(root: str, files: list[str]) -> list[list[str]]:
    groups = defaultdict(list)
    for filename in files:
        path = os.path.join(root, filename)
        text = open(path, "r", encoding="utf-8", errors="replace").read().replace("\r\n", "\n")
        digest = hashlib.sha256(normalize_exact(text).encode("utf-8")).hexdigest()
        groups[digest].append(filename)
    return [sorted(group) for group in groups.values() if len(group) > 1]


def find_semantic_duplicates(root: str, files: list[str]) -> list[list[str]]:
    groups = defaultdict(list)
    for filename in files:
        path = os.path.join(root, filename)
        meta = extract_meta(path)
        normalized_name = kebab(meta["name"])
        detection_hash = hashlib.sha256(normalize_detection(meta["text"]).encode("utf-8")).hexdigest()
        cve = canonical_cve(meta["cve"])
        groups[(detection_hash, normalized_name)].append((filename, cve))

    duplicates = []
    for _, rows in groups.items():
        if len(rows) < 2:
            continue

        by_cve = defaultdict(list)
        for filename, cve in rows:
            by_cve[cve or "__EMPTY__"].append(filename)

        nonempty_cves = [key for key in by_cve if key != "__EMPTY__"]
        if len(nonempty_cves) == 0 or len(nonempty_cves) == 1:
            merged = []
            for names in by_cve.values():
                merged.extend(names)
            if len(merged) > 1:
                duplicates.append(sorted(merged))
        else:
            for names in by_cve.values():
                if len(names) > 1:
                    duplicates.append(sorted(names))

    return duplicates


def main() -> int:
    parser = argparse.ArgumentParser(description="校验模板命名与去重规范")
    parser.add_argument(
        "--root",
        default="/Users/kedaya/.wavely/templates",
        help="模板目录，默认使用 /Users/kedaya/.wavely/templates",
    )
    parser.add_argument(
        "--skip-duplicate-checks",
        action="store_true",
        help="跳过去重相关检查，只校验文件名与 id 规范",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=20,
        help="每类问题最多打印多少条样例，默认 20",
    )
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"错误: 目录不存在: {root}", file=sys.stderr)
        return 2

    files = sorted(f for f in os.listdir(root) if os.path.isfile(os.path.join(root, f)))
    temp_files = find_temp_files(files)
    naming_errors = validate_names(root, files)

    exact_duplicates = []
    semantic_duplicates = []
    if not args.skip_duplicate_checks:
        exact_duplicates = find_exact_duplicates(root, files)
        semantic_duplicates = find_semantic_duplicates(root, files)

    print(f"模板总数: {len(files)}")
    print(f"命名错误数: {len(naming_errors)}")
    print(f"临时文件数: {len(temp_files)}")
    if args.skip_duplicate_checks:
        print("完全重复组: skipped")
        print("语义重复组: skipped")
    else:
        print(f"完全重复组: {len(exact_duplicates)}")
        print(f"语义重复组: {len(semantic_duplicates)}")

    if naming_errors:
        print("\n[命名问题样例]")
        for filename, reason in naming_errors[: args.sample_limit]:
            print(f"- {filename}: {reason}")

    if temp_files:
        print("\n[临时文件样例]")
        for filename in temp_files[: args.sample_limit]:
            print(f"- {filename}")

    if exact_duplicates:
        print("\n[完全重复样例]")
        for group in exact_duplicates[: args.sample_limit]:
            print("- " + ", ".join(group))

    if semantic_duplicates:
        print("\n[语义重复样例]")
        for group in semantic_duplicates[: args.sample_limit]:
            print("- " + ", ".join(group))

    failed = bool(naming_errors or temp_files or exact_duplicates or semantic_duplicates)
    if failed:
        print("\n结果: 校验失败")
        return 1

    print("\n结果: 校验通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
