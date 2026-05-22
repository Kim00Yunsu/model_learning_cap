# trajectory_builder.py

import os
import json
import re
from collections import defaultdict

DATASET_DIR = "reason-pipeline-results"

# ==========================================
# extract last user message
# ==========================================

def extract_last_user_prompt(prompt_text):

    matches = re.findall(

        r'\[user\].*?\n(.*?)(?=\[assistant\]|\Z)',

        prompt_text,

        re.DOTALL

    )

    if not matches:
        return "UNKNOWN"

    return matches[-1].strip()

# ==========================================
# extract json number
# ==========================================

def extract_index(file_name):

    match = re.search(r'-(\d+)\.json', file_name)

    if match:
        return int(match.group(1))

    return 0

# ==========================================
# load json files
# ==========================================

json_files = sorted([
    f for f in os.listdir(DATASET_DIR)
    if f.endswith(".json")
])

# ==========================================
# group trajectories
# ==========================================

trajectories = defaultdict(list)

for file_name in json_files:

    path = os.path.join(
        DATASET_DIR,
        file_name
    )

    try:

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

    except:
        continue

    prompt_text = data.get(
        "prompt_text",
        ""
    )

    last_prompt = extract_last_user_prompt(
        prompt_text
    )

    trajectories[last_prompt].append({

        "file": file_name,

        "index": extract_index(file_name),

        "syscall": data.get("syscall", ""),

        "summary": data.get("summary", ""),

        "reasoning": data.get(
            "reasoning_text",
            ""
        )

    })

# ==========================================
# print trajectories
# ==========================================

for idx, (prompt, actions) in enumerate(
    trajectories.items()
):

    print("\n")
    print("=" * 70)
    print(f"TRAJECTORY #{idx + 1}")
    print("=" * 70)

    print("\n[ USER PROMPT ]")
    print(prompt)

    actions = sorted(
        actions,
        key=lambda x: x["index"]
    )

    print("\n[ ACTION SEQUENCE ]")

    for step, action in enumerate(actions):

        print("\n--------------------------------")
        print(f"STEP #{step + 1}")
        print("--------------------------------")

        print(f"FILE: {action['file']}")
        print(f"SYSCALL: {action['syscall']}")

        summary = action["summary"]

        if summary:
            print(f"SUMMARY: {summary}")