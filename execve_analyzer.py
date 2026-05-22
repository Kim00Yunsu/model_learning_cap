# execve_analyzer.py

import re
import shlex

from risk_checker import rule_base_filter
from target_analyzer import classify_targets


IGNORE_SUMMARY_KEYWORDS = [
    "write 131072 bytes",
    "write 81804 bytes",
    "write 20 bytes",
]


def should_ignore(summary):
    lower = summary.lower()

    for keyword in IGNORE_SUMMARY_KEYWORDS:
        if keyword in lower:
            return True

    return False


def normalize_summary(summary):
    lower = summary.lower().strip()

    if "eval '" in lower:
        try:
            extracted = lower.split("eval '", 1)[1]
            extracted = extracted.split("'", 1)[0]
            return extracted.strip()
        except Exception:
            pass

    if lower.startswith("execve "):
        parts = lower.split()

        if len(parts) >= 3:
            return " ".join(parts[2:])

    return lower


def first_command_token(command):
    try:
        parts = shlex.split(command)
    except Exception:
        parts = command.split()

    if not parts:
        return ""

    token = parts[0]

    if "/" in token:
        token = token.split("/")[-1]

    return token.lower()


def contains_redirect_write(command):
    if ": >" in command:
        return True

    if re.search(r"\s>\s*[/\w\.-]+", command):
        return True

    if re.search(r"\s>>\s*[/\w\.-]+", command):
        return True

    return False


def normalize_action(command):
    s = command.lower().strip()
    cmd = first_command_token(s)

    # 내부 syscall / agent wrapper
    if "openat write-intent open" in s:
        return (
            "internal_write_prepare",
            "파일 쓰기 준비를 위한 내부 open"
        )

    if "source /tmp/agent-home/.claude/shell-snapshots" in s:
        if "eval true" in s or "eval ls" in s or "eval pwd" in s:
            return (
                "internal_shell_wrapper",
                "Agent 내부 쉘 래퍼 실행"
            )

    # safe inspection
    if "git" in s and any(x in s for x in ["ls-files", "status", "diff"]):
        return (
            "git_inspection",
            "Git 저장소 조회"
        )

    if cmd in ["pwd", "which", "whoami", "id", "env", "stat"]:
        return (
            "safe_inspection",
            "환경 또는 파일 상태 조회"
        )

    if s.startswith("test -d") or s.startswith("test -f"):
        return (
            "existence_check",
            "파일 또는 디렉토리 존재 확인"
        )

    if cmd == "file":
        return (
            "file_type_check",
            "파일 타입 조회"
        )

    if cmd in ["ls", "tree"]:
        return (
            "directory_listing",
            "파일 또는 디렉토리 조회"
        )

    if cmd == "cat":
        return (
            "file_read",
            "파일 읽기"
        )

    if cmd in ["find", "bfs", "locate"]:
        return (
            "file_search",
            "파일 검색"
        )

    if cmd in ["head", "tail", "sort", "grep", "ugrep"]:
        return (
            "output_formatting",
            "출력 정리 또는 필터링"
        )

    if cmd == "echo":
        if contains_redirect_write(s):
            return (
                "file_write",
                "파일 생성 또는 내용 작성"
            )

        return (
            "output_formatting",
            "터미널 출력"
        )

    if "|" in s:
        if any(x in s for x in ["grep", "head", "tail", "sort"]):
            if any(x in s for x in ["ls ", "find ", "cat "]):
                return (
                    "output_formatting",
                    "조회 결과 필터링"
                )

    # sensitive / review
    if cmd in ["rm", "unlink", "rmdir"] or "rm -rf" in s:
        return (
            "file_delete",
            "파일 또는 디렉토리 삭제"
        )

    if cmd in ["chmod", "chown"]:
        return (
            "permission_change",
            "권한 또는 소유자 변경"
        )

    if "/dev/shm" in s or "memfd" in s or "mmap" in s or "mprotect" in s:
        if cmd in ["cat", "ls", "find"]:
            return (
                "file_read",
                "메모리 기반 임시 파일 읽기"
            )

        if cmd == "echo" and contains_redirect_write(s):
            return (
                "file_write",
                "메모리 기반 임시 파일 작성"
            )

        return (
            "memory_file",
            "메모리 기반 임시 파일 사용"
        )

    if cmd == "touch":
        return (
            "file_write",
            "파일 생성 또는 내용 작성"
        )

    if contains_redirect_write(s):
        return (
            "file_write",
            "파일 생성 또는 내용 작성"
        )

    if cmd == "mkdir":
        return (
            "directory_create",
            "디렉토리 생성"
        )

    if cmd in ["curl", "wget", "scp", "nc", "netcat"] or "connect" in s or "webfetch" in s:
        return (
            "network_access",
            "외부 네트워크 접근"
        )

    if cmd in ["python", "python3", "node"] or "bash -c" in s or "sh -c" in s:
        return (
            "code_execution",
            "코드 또는 쉘 실행"
        )

    if cmd == "rename":
        return (
            "safe_inspection",
            "임시 파일 이름 변경"
        )

    return (
        "unknown_sensitive",
        "분류되지 않은 실행 동작"
    )


def analyze_execve(syscalls):
    results = []

    for item in syscalls:
        summary = item.get("summary", "")
        syscall = item.get("syscall", "")

        if not summary:
            continue

        if should_ignore(summary):
            continue

        normalized_summary = normalize_summary(summary)
        normalized_action, meaning = normalize_action(normalized_summary)

        target_info = classify_targets(normalized_summary)
        rule_result = rule_base_filter(normalized_action)

        results.append({
            "summary": normalized_summary,
            "meaning": meaning,
            "normalized_action": normalized_action,
            "target_class": target_info["target_class"],
            "execution_binaries": target_info.get("execution_binaries", []),
            "operation_targets": target_info.get("operation_targets", []),
            "rule_result": rule_result,
            "syscall": syscall
        })

    deduped = []
    seen = set()

    for r in results:
        key = (
            r["summary"],
            r["normalized_action"],
            r["target_class"],
            r["rule_result"]
        )

        if key not in seen:
            deduped.append(r)
            seen.add(key)

    return deduped