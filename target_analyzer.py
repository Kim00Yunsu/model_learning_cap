# target_analyzer.py

import re


SANDBOX_PREFIXES = [
    "/tmp/workspace",
]

TEMP_PREFIXES = [
    "/tmp",
]

MEMORY_PREFIXES = [
    "/dev/shm",
]

SYSTEM_CRITICAL_PREFIXES = [
    "/etc",
    "/boot",
    "/lib",
    "/lib64",
    "/sbin",
    "/var/lib",
    "/var/run",
]

CREDENTIAL_KEYWORDS = [
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
    "/etc/shadow",
    "/etc/passwd",
    ".env",
    "token",
    "secret",
    "credential",
]

EXECUTION_BINARY_PREFIXES = [
    "/bin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/sbin/",
]


def extract_paths(text):
    if not text:
        return []

    candidates = re.findall(
        r"(/[A-Za-z0-9._~:/\-]+)",
        text
    )

    cleaned = []

    for path in candidates:
        path = path.strip().rstrip(" ,;)'\"")

        if path and path not in cleaned:
            cleaned.append(path)

    return cleaned


def split_execution_and_targets(paths):
    execution_binaries = []
    operation_targets = []

    for path in paths:
        is_binary = False

        for prefix in EXECUTION_BINARY_PREFIXES:
            if path.startswith(prefix):
                execution_binaries.append(path)
                is_binary = True
                break

        if not is_binary:
            operation_targets.append(path)

    return execution_binaries, operation_targets


def classify_single_target(path):
    lower = path.lower()

    if lower in ["/", "/*"]:
        return "system_root"

    for keyword in CREDENTIAL_KEYWORDS:
        if keyword.lower() in lower:
            return "credential_sensitive"

    for prefix in MEMORY_PREFIXES:
        if lower.startswith(prefix):
            return "memory_temp"

    for prefix in SANDBOX_PREFIXES:
        if lower.startswith(prefix):
            return "sandbox"

    for prefix in TEMP_PREFIXES:
        if lower.startswith(prefix):
            return "temp"

    for prefix in SYSTEM_CRITICAL_PREFIXES:
        if lower.startswith(prefix):
            return "system_critical"

    if lower.startswith("/home/") or lower.startswith("/users/"):
        return "user_home"

    return "unknown_path"


TARGET_PRIORITY = [
    "system_root",
    "credential_sensitive",
    "system_critical",
    "user_home",
    "memory_temp",
    "sandbox",
    "temp",
    "unknown_path",
]


def classify_targets(summary):
    paths = extract_paths(summary)

    execution_binaries, operation_targets = split_execution_and_targets(paths)

    if not operation_targets:
        return {
            "execution_binaries": execution_binaries,
            "operation_targets": [],
            "target_class": "no_explicit_target",
        }

    target_classes = [
        classify_single_target(target)
        for target in operation_targets
    ]

    final_class = "unknown_path"

    for priority in TARGET_PRIORITY:
        if priority in target_classes:
            final_class = priority
            break

    return {
        "execution_binaries": execution_binaries,
        "operation_targets": operation_targets,
        "target_class": final_class,
    }


def policy_decision_for_action(action):
    """
    정책은 극단적으로 위험한 경우만 BLOCK한다.
    sandbox 내부의 일반 파일 생성/권한 변경/디렉토리 생성은
    Guard LLM의 semantic 판단을 우선한다.
    """

    normalized_action = action.get("normalized_action", "")
    target_class = action.get("target_class", "")

    if target_class in [
        "system_root",
        "credential_sensitive",
        "system_critical",
        "user_home",
    ]:
        if normalized_action in [
            "file_delete",
            "permission_change",
            "file_write",
            "directory_create",
            "code_execution",
        ]:
            return (
                "block",
                "Action modifies or executes against a critical or sensitive target."
            )

    if normalized_action == "file_delete":
        if target_class in ["sandbox", "temp", "memory_temp"]:
            return (
                "confirm",
                "Deletion is destructive but limited to a non-critical target."
            )

    if normalized_action == "network_access":
        return (
            "confirm",
            "External network access requires user confirmation."
        )

    if normalized_action == "memory_file":
        if target_class == "memory_temp":
            return (
                "confirm",
                "Memory-based file operation requires confirmation if executable behavior is involved."
            )

    return "allow", ""