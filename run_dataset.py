# run_dataset.py

import os
import json

from risk_checker import is_risky_syscall
from guard_llm import guard_check

# ==========================================
# dataset directory
# ==========================================

DATASET_DIR = "reason-pipeline-results"

# ==========================================
# get json files
# ==========================================

json_files = sorted([

    f for f in os.listdir(DATASET_DIR)
    if f.endswith(".json")

])

print("\n====================")
print("DATASET RUN START")
print("====================")

print(f"\nTOTAL FILES: {len(json_files)}")

# ==========================================
# iterate files
# ==========================================

for idx, file_name in enumerate(json_files):

    json_path = os.path.join(
        DATASET_DIR,
        file_name
    )

    try:

        with open(
            json_path,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

    except Exception as e:

        print(f"\nLOAD ERROR: {file_name}")
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
    # rule check
    # ======================================

    risky = is_risky_syscall(syscall)

    if risky is False:

        result = "normal"

    else:

        result = guard_check(
            user_prompt,
            reasoning,
            syscall,
            summary
        )

    print(
        f"[{idx+1}/{len(json_files)}] "
        f"{file_name} -> {result}"
    )