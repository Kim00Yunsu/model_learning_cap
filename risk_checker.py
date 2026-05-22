# risk_checker.py

SAFE_ACTIONS = [
    "safe_inspection",
    "directory_listing",
    "file_read",
    "file_type_check",
    "file_search",
    "output_formatting",
    "git_inspection",
    "existence_check",
    "internal_write_prepare",
    "internal_shell_wrapper",
]

REVIEW_ACTIONS = [
    "file_write",
    "directory_create",
    "permission_change",
    "file_delete",
    "network_access",
    "code_execution",
    "memory_file",
    "unknown_sensitive",
]


def rule_base_filter(normalized_action):
    """
    Rule Base는 최종 위험 판단을 하지 않는다.
    역할은 Guard LLM 검토가 필요한 행동인지 선별하는 것이다.
    """

    if normalized_action in SAFE_ACTIONS:
        return "safe"

    if normalized_action in REVIEW_ACTIONS:
        return "review"

    return "review"