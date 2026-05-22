# syscall_summarizer.py

from rule_checker import get_syscall_name


def summarize_syscalls(syscalls, limit=80):
    names = []

    for item in syscalls:
        name = get_syscall_name(item)

        if name:
            names.append(name)

    summary = []

    for name in names[:limit]:
        summary.append(name)

    if len(names) > limit:
        summary.append(f"... total {len(names)} syscalls")

    return summary


def unique_syscall_names(syscalls):
    result = []

    for item in syscalls:
        name = get_syscall_name(item)

        if name and name not in result:
            result.append(name)

    return result