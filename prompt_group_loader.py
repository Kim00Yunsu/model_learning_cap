# prompt_group_loader.py

import os
import json
import re


def load_json_files(folder_path):
    files = []

    for name in os.listdir(folder_path):
        if name.endswith(".json"):
            files.append(name)

    def sort_key(filename):
        nums = re.findall(r"\d+", filename)
        return [int(x) for x in nums] if nums else [0]

    files.sort(key=sort_key)

    data_list = []

    for name in files:
        path = os.path.join(folder_path, name)

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            data["_filename"] = name
            data_list.append(data)

        except Exception as e:
            print(f"[LOAD ERROR] {name} : {e}")

    return data_list


def find_text_by_keys(data, keys):
    if isinstance(data, dict):
        for k, v in data.items():
            if k in keys and isinstance(v, str):
                return v

        for v in data.values():
            result = find_text_by_keys(v, keys)
            if result:
                return result

    elif isinstance(data, list):
        for item in data:
            result = find_text_by_keys(item, keys)
            if result:
                return result

    return ""


def extract_user_prompt(data):
    return find_text_by_keys(data, [
        "user_prompt",
        "userPrompt",
        "prompt",
        "request",
        "user_request",
        "input"
    ])


def extract_reasoning(data):
    return find_text_by_keys(data, [
        "reasoning",
        "agent_reasoning",
        "assistant_reasoning",
        "thought",
        "analysis"
    ])


def collect_syscalls(data):
    result = []

    def walk(x):
        if isinstance(x, dict):
            syscall = None

            for key in ["syscall", "syscall_name", "name"]:
                if key in x and isinstance(x[key], str):
                    syscall = x[key]
                    break

            if syscall:
                result.append(x)

            for v in x.values():
                walk(v)

        elif isinstance(x, list):
            for item in x:
                walk(item)

    walk(data)
    return result


def group_by_prompt(folder_path):
    raw_logs = load_json_files(folder_path)

    groups = []
    current_group = None
    last_prompt = None

    for data in raw_logs:
        prompt = extract_user_prompt(data).strip()
        reasoning = extract_reasoning(data).strip()
        syscalls = collect_syscalls(data)

        if not prompt:
            prompt = last_prompt

        if not prompt:
            prompt = "UNKNOWN_PROMPT"

        if current_group is None or prompt != last_prompt:
            current_group = {
                "prompt_id": len(groups) + 1,
                "user_prompt": prompt,
                "agent_reasoning": "",
                "logs": [],
                "syscalls": []
            }
            groups.append(current_group)

        if reasoning and reasoning not in current_group["agent_reasoning"]:
            current_group["agent_reasoning"] += reasoning + "\n"

        current_group["logs"].append(data)
        current_group["syscalls"].extend(syscalls)

        last_prompt = prompt

    return groups