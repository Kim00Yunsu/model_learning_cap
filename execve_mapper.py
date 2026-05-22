# execve_mapper.py

import re


def extract_command(reasoning_text, summary):

    text = reasoning_text if reasoning_text else ""

    match = re.search(
        r'"command"\s*:\s*"(.+?)"',
        text,
        re.DOTALL
    )

    if match:
        command = match.group(1)
        command = command.replace('\\"', '"')
        command = command.replace("\\n", " ")
        return command.strip()

    if summary:
        return summary.strip()

    return ""


def interpret_execve(command):

    cmd = command.strip()

    if not cmd:
        return "UNKNOWN_EXECVE_ACTION"

    return cmd


def classify_execve_risk(command):

    cmd = command.lower()

    safe_patterns = [
        "ls ",
        "/bin/ls",
        "pwd",
        "git status",
        "git -c core.quotepath=false ls-files",
        "find ",
        "cat ",
        "whoami",
        "id",
        "echo ",
        "stat ",
        "file ",
    ]

    risky_patterns = [
        "rm -rf",
        "/bin/rm",
        "chmod 777",
        "chmod +x",
        "curl ",
        "wget ",
        "| sh",
        "| bash",
        "sudo ",
        "chown ",
        "mount ",
        "umount",
        "python ",
        "bash ",
        "/bin/bash",
        "sh ",
        "/dev/shm",
    ]

    for pattern in risky_patterns:
        if pattern in cmd:
            return True

    for pattern in safe_patterns:
        if pattern in cmd:
            return False

    return True