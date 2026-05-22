# semantic_mapper.py

# =========================================================
# coarse-grained semantic categories
# =========================================================

SAFE_SEMANTICS = [

    "INFORMATION_GATHERING",

]

RISKY_SEMANTICS = [

    "FILE_MODIFICATION",
    "DESTRUCTIVE_ACTION",
    "PERMISSION_MODIFICATION",
    "NETWORK_ACCESS",
    "CODE_EXECUTION",
    "PROCESS_EXECUTION",

]

# =========================================================
# execve semantic abstraction
# =========================================================

def semanticize_execve(command):

    cmd = command.lower().strip()

    if not cmd:
        return "UNKNOWN_ACTION"

    # =====================================================
    # destructive
    # =====================================================

    destructive_keywords = [

        "rm ",
        "unlink",
        "rmdir",

    ]

    for keyword in destructive_keywords:

        if keyword in cmd:
            return "DESTRUCTIVE_ACTION"

    # =====================================================
    # permission
    # =====================================================

    permission_keywords = [

        "chmod",
        "chown",
        "sudo",

    ]

    for keyword in permission_keywords:

        if keyword in cmd:
            return "PERMISSION_MODIFICATION"

    # =====================================================
    # network
    # =====================================================

    network_keywords = [

        "curl ",
        "wget ",
        "scp ",
        "ssh ",

    ]

    for keyword in network_keywords:

        if keyword in cmd:
            return "NETWORK_ACCESS"

    # =====================================================
    # code execution
    # =====================================================

    code_keywords = [

        "python ",
        "bash ",
        "/bin/bash",
        "sh ",

    ]

    for keyword in code_keywords:

        if keyword in cmd:
            return "CODE_EXECUTION"

    # =====================================================
    # file modification
    # =====================================================

    modification_keywords = [

        "touch ",
        "echo ",
        ": >",
        "mv ",
        "cp ",
        "rename",

    ]

    for keyword in modification_keywords:

        if keyword in cmd:
            return "FILE_MODIFICATION"

    # =====================================================
    # information gathering
    # =====================================================

    info_keywords = [

        "ls ",
        "find ",
        "cat ",
        "pwd",
        "whoami",
        "id",
        "stat ",
        "file ",
        "git status",
        "git -c",
        "git ls-files",

    ]

    for keyword in info_keywords:

        if keyword in cmd:
            return "INFORMATION_GATHERING"

    # =====================================================
    # default
    # =====================================================

    return "PROCESS_EXECUTION"

# =========================================================
# syscall semantic abstraction
# =========================================================

def semanticize_syscall(syscall):

    if syscall in [

        "open",
        "openat",
        "read",
        "stat",
        "fstat",

    ]:

        return "INFORMATION_GATHERING"

    if syscall in [

        "write",
        "rename",
        "renameat",
        "renameat2",
        "mkdir",
        "mkdirat",

    ]:

        return "FILE_MODIFICATION"

    if syscall in [

        "unlink",
        "unlinkat",
        "rmdir",

    ]:

        return "DESTRUCTIVE_ACTION"

    if syscall in [

        "chmod",
        "fchmod",
        "fchmodat",
        "chown",

    ]:

        return "PERMISSION_MODIFICATION"

    if syscall in [

        "connect",
        "sendto",
        "sendmsg",

    ]:

        return "NETWORK_ACCESS"

    if syscall in [

        "execve",

    ]:

        return "PROCESS_EXECUTION"

    return "UNKNOWN_ACTION"

# =========================================================
# semantic risk
# =========================================================

def is_risky_semantic(semantic):

    if semantic in SAFE_SEMANTICS:
        return False

    if semantic in RISKY_SEMANTICS:
        return True

    return True