# run_real_trajectory.py

import os
import json
import re

from risk_checker import is_risky_syscall
from guard_llm import guard_check

from semantic_mapper import (
    infer_semantic_action,
    semantic_action_to_syscall
)

# ==========================================
# dataset directory
# ==========================================

DATASET_DIR = "reason-pipeline-results"

# ==========================================
# get all json files
# ==========================================

json_files = sorted([

    f for f in os.listdir(DATASET_DIR)
    if f.endswith(".json")

])

# ==========================================
# summarize prompt
# ==========================================

def summarize_prompt(text):

    text = text.replace("\n", " ")

    text = re.sub(r"\s+", " ", text)

    if len(text) > 140:

        text = text[:140] + " ..."

    return text.strip()

# ==========================================
# extract command
# ==========================================

def extract_command(reasoning):

    match = re.search(

        r'"command"\s*:\s*"(.+?)"',
        reasoning,
        re.DOTALL

    )

    if match:

        cmd = match.group(1)

        cmd = cmd.replace('\\"', '"')

        return cmd

    return reasoning.strip()

# ==========================================
# start
# ==========================================

print("\n")
print("=" * 60)
print("ARGUS REAL TRAJECTORY ANALYSIS")
print("=" * 60)

print(f"\nTOTAL FILES: {len(json_files)}")

# ==========================================
# iterate json files
# ==========================================

for idx, file_name in enumerate(json_files):

    print("\n\n")
    print("=" * 60)
    print(f"EVENT #{idx + 1}")
    print(f"FILE: {file_name}")
    print("=" * 60)

    json_path = os.path.join(
        DATASET_DIR,
        file_name
    )

    # ======================================
    # load json
    # ======================================

    try:

        with open(
            json_path,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

    except Exception as e:

        print("\nLOAD ERROR")
        print(e)

        continue

    # ======================================
    # extract fields
    # ======================================

    user_prompt = data.get(
        "prompt_text",
        ""
    )

    reasoning = data.get(
        "reasoning_text",
        ""
    )

    syscall = data.get(
        "syscall",
        ""
    )

    summary = data.get(
        "summary",
        ""
    )

    # ======================================
    # summarized prompt
    # ======================================

    short_prompt = summarize_prompt(
        user_prompt
    )

    # ======================================
    # extract actual command
    # ======================================

    actual_command = extract_command(
        reasoning
    )

    # ======================================
    # print event info
    # ======================================

    print("\n")
    print("-" * 60)
    print("[ USER REQUEST ]")
    print("-" * 60)

    print("\n" + short_prompt)

    print("\n")
    print("-" * 60)
    print("[ ACTUAL COMMAND ]")
    print("-" * 60)

    print("\n" + actual_command)

    print("\n")
    print("-" * 60)
    print("[ ORIGINAL SYSCALL ]")
    print("-" * 60)

    print("\n" + syscall)

    # ======================================
    # semantic analysis for execve
    # ======================================

    semantic_action = None

    semantic_syscall = syscall

    if syscall == "execve":

        semantic_action = infer_semantic_action(
            command=actual_command,
            syscall=syscall
        )

        semantic_syscall = semantic_action_to_syscall(
            semantic_action
        )

        print("\n")
        print("-" * 60)
        print("[ SEMANTIC ACTION ]")
        print("-" * 60)

        print("\n" + semantic_action)

        print("\n")
        print("-" * 60)
        print("[ SEMANTIC SYSCALL ]")
        print("-" * 60)

        print("\n" + semantic_syscall)

    # ======================================
    # step 1 : rule check
    # ======================================

    print("\n")
    print("=" * 60)
    print("STEP 1 : RULE CHECK")
    print("=" * 60)

    risky = is_risky_syscall(
        semantic_syscall
    )

    # ======================================
    # safe syscall
    # ======================================

    if risky is False:

        print("\nRESULT:")
        print("SAFE SYSCALL")

        print("\n")
        print("=" * 60)
        print("FINAL POLICY")
        print("=" * 60)

        print("\nALLOW")

        continue

    # ======================================
    # risky syscall
    # ======================================

    print("\nRESULT:")
    print("RISKY SYSCALL")

    print("\nACTION:")
    print("SEND TO GUARD LLM")

    # ======================================
    # step 2 : guard llm
    # ======================================

    print("\n")
    print("=" * 60)
    print("STEP 2 : GUARD LLM")
    print("=" * 60)

    result = guard_check(

        user_prompt=user_prompt,

        reasoning=reasoning,

        syscall=semantic_syscall,

        summary=actual_command

    )

    print("\nGUARD RESULT:")
    print(result)

    # ======================================
    # final policy
    # ======================================

    print("\n")
    print("=" * 60)
    print("FINAL POLICY")
    print("=" * 60)

    if result == "normal":

        print("\nALLOW")

    elif result == "ambiguous":

        print("\nASK USER CONFIRMATION")

    elif result == "harmful":

        print("\nBLOCK")

    else:

        print("\nUNKNOWN")