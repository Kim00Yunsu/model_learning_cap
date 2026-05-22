# rule_checker.py

import json


def load_mapping(mapping_path):
    with open(mapping_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_syscall_name(syscall_obj):
    for key in ["syscall", "syscall_name", "name"]:
        if key in syscall_obj:
            return str(syscall_obj[key])

    return ""


def check_risky_syscalls(syscalls, mapping):
    risky = []
    safe = []

    for item in syscalls:
        name = get_syscall_name(item)

        if not name:
            continue

        risk_value = mapping.get(name, 0)

        if risk_value == 1:
            risky.append(item)
        else:
            safe.append(item)

    return {
        "has_risky": len(risky) > 0,
        "risky_syscalls": risky,
        "safe_syscalls": safe
    }