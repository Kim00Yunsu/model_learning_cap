# conversation_timeline_parser.py

import os
import json
import re
from datetime import datetime


# =========================================
# SYSTEM OUTPUT FILTER
# =========================================

SYSTEM_OUTPUT_PATTERNS = [

    "exit code",
    "bash completed",
    "file does not exist",
    "file content",
    "tool_use_error",
    "has not been read yet",
    "maximum allowed size",
    "note: your current working directory",
    "-rw-r--r--",
    "created successfully at:",
]


# =========================================
# QUESTION / CHOICE DETECTION
# =========================================

QUESTION_PATTERNS = [

    "어떤",
    "무엇",
    "선택",
    "입력",
    "원하",
    "진행",
    "하시겠",
    "해주세요",
    "please choose",
    "select",
    "which",
    "what would you like",
]


CHOICE_LINE_PATTERNS = [

    r"^\s*1[\.\)]",
    r"^\s*2[\.\)]",
    r"^\s*3[\.\)]",
    r"^\s*4[\.\)]",
    r"^\s*-\s",
]


# =========================================
# SYSTEM OUTPUT CHECK
# =========================================

def is_system_output(text):

    lower = text.lower().strip()

    if not lower:
        return True

    for pattern in SYSTEM_OUTPUT_PATTERNS:

        if pattern.lower() in lower:
            return True

    if lower.startswith("<tool_use_error>"):
        return True

    if lower.startswith("(") and "bash" in lower:
        return True

    return False


# =========================================
# ASSISTANT QUESTION DETECTOR
# =========================================

def assistant_is_waiting_response(text):

    lower = text.lower()

    # keyword-based question
    for pattern in QUESTION_PATTERNS:

        if pattern.lower() in lower:
            return True

    # numbered choices
    lines = lower.splitlines()

    count = 0

    for line in lines:

        for p in CHOICE_LINE_PATTERNS:

            if re.search(p, line):
                count += 1

    if count >= 2:
        return True

    # explicit question mark
    if "?" in lower:
        return True

    return False


# =========================================
# SHORT USER RESPONSE
# =========================================

def is_short_response(text):

    cleaned = text.strip()

    if len(cleaned) <= 15:
        return True

    if len(cleaned.split()) <= 2:
        return True

    return False


# =========================================
# VALID USER INTENT
# =========================================

def is_real_user_intent(text):

    if is_system_output(text):
        return False

    if len(text.strip()) <= 1:
        return False

    return True


# =========================================
# JSON LOAD
# =========================================

def load_json_files(folder_path):

    results = []

    for name in os.listdir(folder_path):

        if not name.endswith(".json"):
            continue

        path = os.path.join(
            folder_path,
            name
        )

        try:

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as f:

                data = json.load(f)

            data["_filename"] = name

            results.append(data)

        except Exception as e:

            print(
                f"[LOAD ERROR] {name}: {e}"
            )

    def sort_key(item):

        created_at = item.get(
            "created_at",
            ""
        )

        if created_at:

            try:

                return datetime.fromisoformat(
                    created_at.replace(
                        "Z",
                        "+00:00"
                    )
                )

            except Exception:
                pass

        nums = re.findall(
            r"\d+",
            item.get("_filename", "")
        )

        return [int(x) for x in nums] if nums else [0]

    results.sort(key=sort_key)

    return results


# =========================================
# PROMPT CLEAN
# =========================================

def clean_prompt(text):

    text = text.strip()

    text = re.sub(
        r"\[([^\]]+)\]\([^)]+\)",
        r"\1",
        text
    )

    return text.strip()


# =========================================
# BLOCK EXTRACTION
# =========================================

def extract_blocks(prompt_text):

    if not prompt_text:
        return []

    pattern = (
        r"\[(user|assistant)\]\s*#\d+\s*"
        r"(.*?)"
        r"(?=\[(?:assistant|user)\]\s*#\d+|\Z)"
    )

    matches = re.findall(
        pattern,
        prompt_text,
        flags=re.DOTALL
    )

    blocks = []

    for role, content in matches:

        cleaned = clean_prompt(content)

        if cleaned:

            blocks.append({

                "role": role,
                "content": cleaned
            })

    return blocks


# =========================================
# INTENT CREATION
# =========================================

def create_intent(
    intents,
    prompt_to_intent,
    main_prompt
):

    if main_prompt in prompt_to_intent:
        return prompt_to_intent[main_prompt]

    intent = {

        "intent_id":
            len(intents) + 1,

        "user_prompt":
            main_prompt,

        "follow_up_inputs":
            [],

        "reasoning":
            [],

        "syscalls":
            []
    }

    prompt_to_intent[
        main_prompt
    ] = intent

    intents.append(intent)

    return intent


# =========================================
# REASONING
# =========================================

def add_reasoning(intent, log):

    reasoning = log.get(
        "reasoning_text",
        ""
    )

    summary = log.get(
        "summary",
        ""
    )

    if reasoning:

        if reasoning not in intent["reasoning"]:

            intent["reasoning"].append(
                reasoning
            )

    elif summary:

        simple_reason = (
            f"Action summary: {summary}"
        )

        if simple_reason not in intent["reasoning"]:

            intent["reasoning"].append(
                simple_reason
            )


# =========================================
# MAIN TIMELINE BUILDER
# =========================================

def build_intent_timeline(folder_path):

    logs = load_json_files(folder_path)

    intents = []
    prompt_to_intent = {}

    current_main_intent = None

    # 핵심 추가
    pending_question_intent = None

    for log in logs:

        prompt_text = log.get(
            "prompt_text",
            ""
        )

        blocks = extract_blocks(
            prompt_text
        )

        latest_user = None
        latest_assistant = None

        # =====================================
        # latest block extraction
        # =====================================

        for block in reversed(blocks):

            if (
                latest_user is None
                and block["role"] == "user"
            ):
                latest_user = block["content"]

            if (
                latest_assistant is None
                and block["role"] == "assistant"
            ):
                latest_assistant = block["content"]

            if latest_user and latest_assistant:
                break

        # =====================================
        # assistant asked question?
        # =====================================

        if latest_assistant:

            if assistant_is_waiting_response(
                latest_assistant
            ):

                if current_main_intent:
                    pending_question_intent = (
                        current_main_intent
                    )

        # =====================================
        # invalid user
        # =====================================

        if not latest_user:
            continue

        if not is_real_user_intent(
            latest_user
        ):
            continue

        # =====================================
        # follow-up response
        # =====================================

        if (
            pending_question_intent
            and is_short_response(
                latest_user
            )
        ):

            intent = create_intent(
                intents,
                prompt_to_intent,
                pending_question_intent
            )

            if (
                latest_user
                not in intent[
                    "follow_up_inputs"
                ]
            ):

                intent[
                    "follow_up_inputs"
                ].append(
                    latest_user
                )

            # 핵심:
            # follow-up 이후 syscall도
            # 기존 intent에 연결됨

            intent["syscalls"].append(
                log
            )

            add_reasoning(
                intent,
                log
            )

            # 질문 처리 완료
            pending_question_intent = None

            continue

        # =====================================
        # new semantic intent
        # =====================================

        current_main_intent = latest_user

        intent = create_intent(
            intents,
            prompt_to_intent,
            current_main_intent
        )

        intent["syscalls"].append(
            log
        )

        add_reasoning(
            intent,
            log
        )

    return intents