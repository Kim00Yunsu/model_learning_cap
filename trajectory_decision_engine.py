# trajectory_decision_engine.py

import os
import json
import re
from collections import defaultdict

from risk_checker import is_risky_syscall

from guard_llm import (
    guard_check
)

from semantic_mapper import (
    semanticize_execve,
    semanticize_syscall,
    is_risky_semantic
)

DATASET_DIR = "reason-pipeline-results"

# =========================================================
# file index
# =========================================================

def extract_index(file_name):

    match = re.search(
        r'-(\d+)\.json',
        file_name
    )

    if match:
        return int(match.group(1))

    return 0

# =========================================================
# clean text
# =========================================================

def clean_text(text):

    text = text.replace("\n", " ")
    text = re.sub(r"\s+", " ", text)

    return text.strip()

# =========================================================
# user prompt extraction
# =========================================================

def extract_last_user_prompt(prompt_text):

    matches = re.findall(

        r'\[user\]\s*#\d+\s*(.*?)(?=\[assistant\]|\[user\]|\Z)',

        prompt_text,

        re.DOTALL

    )

    cleaned = []

    for m in matches:

        t = clean_text(m)

        # ==============================================
        # skip runtime metadata
        # ==============================================

        if not t:
            continue

        if len(t) <= 2:
            continue

        if "Exit code" in t:
            continue

        if "(Bash completed with no output)" in t:
            continue

        if "tool_use_error" in t:
            continue

        if "File content" in t:
            continue

        if "File does not exist" in t:
            continue

        cleaned.append(t)

    if not cleaned:
        return "UNKNOWN"

    return cleaned[-1]

# =========================================================
# command extraction
# =========================================================

def extract_command(reasoning_text, summary):

    text = reasoning_text if reasoning_text else ""

    # ==============================================
    # command field
    # ==============================================

    match = re.search(

        r'"command"\s*:\s*"(.+?)"',

        text,

        re.DOTALL

    )

    if match:

        cmd = match.group(1)

        cmd = cmd.replace('\\"', '"')
        cmd = cmd.replace("\\n", " ")

        return cmd.strip()

    # ==============================================
    # fallback
    # ==============================================

    if summary:

        summary = summary.replace("\n", " ")

        return summary.strip()

    return "UNKNOWN_COMMAND"

# =========================================================
# load json files
# =========================================================

json_files = sorted(

    [
        f for f in os.listdir(DATASET_DIR)
        if f.endswith(".json")
    ],

    key=extract_index

)

# =========================================================
# trajectory grouping
# =========================================================

trajectories = defaultdict(list)

for file_name in json_files:

    path = os.path.join(
        DATASET_DIR,
        file_name
    )

    try:

        with open(
            path,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

    except Exception as e:

        print("LOAD ERROR:", file_name)
        print(e)

        continue

    prompt = extract_last_user_prompt(
        data.get("prompt_text", "")
    )

    trajectories[prompt].append({

        "file": file_name,

        "index": extract_index(file_name),

        "syscall": data.get("syscall", ""),

        "summary": data.get("summary", ""),

        "reasoning": data.get("reasoning_text", "")

    })

# =========================================================
# trajectory analysis
# =========================================================

for idx, (prompt, actions) in enumerate(trajectories.items()):

    actions = sorted(
        actions,
        key=lambda x: x["index"]
    )

    print("\n")
    print("=" * 70)
    print(f"TRAJECTORY #{idx + 1}")
    print("=" * 70)

    print("\n[ USER PROMPT ]")
    print(prompt)

    real_syscalls = []

    execve_actions = []

    semantic_flow = []

    risky_detected = False

    seen_execve = set()

    # =====================================================
    # action loop
    # =====================================================

    for action in actions:

        syscall = action["syscall"]

        summary = action["summary"]

        reasoning = action["reasoning"]

        command = extract_command(
            reasoning,
            summary
        )

        real_syscalls.append(syscall)

        # =================================================
        # execve semantic abstraction
        # =================================================

        if syscall == "execve":

            if command not in seen_execve:

                execve_actions.append(command)

                seen_execve.add(command)

            semantic_action = semanticize_execve(
                command
            )

            semantic_flow.append(
                semantic_action
            )

            if is_risky_semantic(
                semantic_action
            ):

                risky_detected = True

        # =================================================
        # syscall semantic abstraction
        # =================================================

        else:

            semantic_action = semanticize_syscall(
                syscall
            )

            semantic_flow.append(
                semantic_action
            )

            if is_risky_syscall(syscall):

                risky_detected = True

    # =====================================================
    # output
    # =====================================================

    print("\n")
    print("-" * 70)
    print("[ REAL SYSCALL SEQUENCE ]")
    print("-" * 70)

    for i, syscall in enumerate(real_syscalls):

        print(f"#{i + 1} {syscall}")

    print("\n")
    print("-" * 70)
    print("[ EXECVE ACTUAL ACTIONS ]")
    print("-" * 70)

    if execve_actions:

        for i, action in enumerate(execve_actions):

            print(f"#{i + 1} {action}")

    else:

        print("No execve actions")

    print("\n")
    print("-" * 70)
    print("[ SEMANTIC FLOW ]")
    print("-" * 70)

    for i, action in enumerate(semantic_flow):

        print(f"#{i + 1} {action}")

    # =====================================================
    # rule filter
    # =====================================================

    print("\n")
    print("-" * 70)
    print("[ RULE-BASED FILTER ]")
    print("-" * 70)

    # =====================================================
    # risky trajectory
    # =====================================================

    if risky_detected:

        print("\nRESULT:")
        print("RISKY TRAJECTORY")

        print("\nACTION:")
        print("SEND TO GUARD LLM")

        # =================================================
        # guard llm
        # =================================================

        result = guard_check(

            user_prompt=prompt,

            real_syscalls=real_syscalls,

            execve_actions=execve_actions,

            semantic_flow=semantic_flow

        )

        print("\n")
        print("-" * 70)
        print("[ GUARD LLM RESULT ]")
        print("-" * 70)

        print("\nLABEL:")
        print(result["label"])

        print("\nREASON:")
        print(result["reason"])

        # =================================================
        # final policy
        # =================================================

        print("\n")
        print("-" * 70)
        print("[ FINAL POLICY ]")
        print("-" * 70)

        if result["label"] == "normal":

            print("\nALLOW")

        elif result["label"] == "ambiguous":

            print("\nASK USER CONFIRMATION")

        elif result["label"] == "harmful":

            print("\nBLOCK")

        else:

            print("\nUNKNOWN")

    # =====================================================
    # safe trajectory
    # =====================================================

    else:

        print("\nRESULT:")
        print("SAFE TRAJECTORY")

        print("\n")
        print("-" * 70)
        print("[ FINAL POLICY ]")
        print("-" * 70)

        print("\nALLOW")