# decision_engine.py

from conversation_timeline_parser import build_intent_timeline
from execve_analyzer import analyze_execve
from guard_llm import guard_check


LOG_FOLDER = "./reason-pipeline-results"


def label_to_decision(label):
    """
    Guard LLM은 반드시 두 가지 label만 출력한다.

    normal  -> ALLOW
    harmful -> USER_CONFIRM

    여기서 harmful은 즉시 차단이 아니라,
    사용자 확인이 필요한 위험 가능 행동을 의미한다.
    """

    label = str(label).lower().strip()

    if label == "normal":
        return "ALLOW"

    if label == "harmful":
        return "USER_CONFIRM"

    return "USER_CONFIRM"


def decision_reason_from_label(label):
    label = str(label).lower().strip()

    if label == "normal":
        return "Guard LLM classified the reviewed action as normal."

    if label == "harmful":
        return "Guard LLM classified the reviewed action as harmful."

    return "Guard LLM returned an unknown label, so user confirmation is required."


def print_reasoning(reasoning):
    if not reasoning:
        print("No reasoning detected.")
        return

    text = "\n".join(reasoning)

    if len(text) > 1200:
        print(text[:1200])
        print("... [truncated]")
    else:
        print(text)


def print_follow_ups(follow_up_inputs):
    if not follow_up_inputs:
        print("No follow-up input.")
        return

    for item in follow_up_inputs:
        print(f"- {item}")


def split_actions(actions):
    safe = []
    review = []

    for action in actions:
        if action["rule_result"] == "safe":
            safe.append(action)
        else:
            review.append(action)

    return safe, review


def summarize_actions(actions):
    counter = {}

    for action in actions:
        key = action["normalized_action"]
        counter[key] = counter.get(key, 0) + 1

    return counter


def argv_to_text(argv):
    if isinstance(argv, list):
        return " ".join(str(x) for x in argv)

    if argv is None:
        return ""

    return str(argv)


def get_agent_name_from_syscalls(syscalls):
    names = []

    for syscall in syscalls:
        name = syscall.get("agent_name", "unknown")

        if name and name not in names:
            names.append(name)

    if not names:
        return "unknown"

    return ", ".join(names)


def normalize_raw_summary(raw):
    if raw is None:
        return ""

    text = str(raw).strip()

    if text.startswith("execve "):
        text = text[len("execve "):].strip()

    return text


def find_matching_syscall(action, syscalls):
    action_summary = str(action.get("summary", "")).strip()

    if not action_summary:
        return None

    for syscall in syscalls:
        raw_summary = normalize_raw_summary(syscall.get("summary", ""))

        if not raw_summary:
            continue

        if action_summary in raw_summary:
            return syscall

        if raw_summary in action_summary:
            return syscall

    for syscall in syscalls:
        argv_text = argv_to_text(syscall.get("argv", []))

        if not argv_text:
            continue

        if action_summary in argv_text:
            return syscall

        if argv_text in action_summary:
            return syscall

    for syscall in syscalls:
        path = syscall.get("path", "")
        argv_text = argv_to_text(syscall.get("argv", []))

        if path and path in action_summary:
            return syscall

        if argv_text:
            first_token = argv_text.split()[0]

            if first_token and first_token in action_summary:
                return syscall

    return None


def attach_syscall_metadata(actions, syscalls):
    enriched_actions = []

    for action in actions:
        matched = find_matching_syscall(action, syscalls)
        new_action = dict(action)

        if matched:
            new_action["agent_name"] = matched.get("agent_name", "unknown")
            new_action["event_id"] = matched.get("event_id", "")
            new_action["syscall"] = matched.get("syscall", "")
            new_action["path"] = matched.get("path", "")
            new_action["argv"] = matched.get("argv", [])
            new_action["raw_summary"] = matched.get("summary", "")
            new_action["created_at"] = matched.get("created_at", "")
        else:
            new_action["agent_name"] = "unknown"
            new_action["event_id"] = ""
            new_action["syscall"] = ""
            new_action["path"] = ""
            new_action["argv"] = []
            new_action["raw_summary"] = ""
            new_action["created_at"] = ""

        enriched_actions.append(new_action)

    return enriched_actions


def print_action_detail(idx, action):
    argv_text = argv_to_text(action.get("argv", []))

    print(f"\n[ACTION #{idx}]")
    print("agent name        :", action.get("agent_name", "unknown"))
    print("event id          :", action.get("event_id", ""))
    print("created at        :", action.get("created_at", ""))
    print("syscall           :", action.get("syscall", ""))
    print("path              :", action.get("path", ""))
    print("argv              :", argv_text)
    print("raw summary       :", action.get("raw_summary", ""))
    print("summary           :", action["summary"])
    print("meaning           :", action["meaning"])
    print("normalized action :", action["normalized_action"])
    print("target class      :", action["target_class"])
    print("rule result       :", action["rule_result"])


def run():
    intents = build_intent_timeline(LOG_FOLDER)

    print("\n====================================")
    print("ARGUS INTENT ANALYSIS")
    print("====================================")
    print(f"Detected intents : {len(intents)}")

    for intent in intents:
        user_prompt = intent["user_prompt"]
        follow_up_inputs = intent.get("follow_up_inputs", [])
        reasoning = intent["reasoning"]
        syscalls = intent["syscalls"]

        actions = analyze_execve(syscalls)
        actions = attach_syscall_metadata(actions, syscalls)
        safe_actions, review_actions = split_actions(actions)

        print("\n\n==================================================")
        print(f"INTENT {intent['intent_id']}")
        print("==================================================")

        print("\n[AI AGENT]")
        print("agent name :", get_agent_name_from_syscalls(syscalls))

        print("\n[MAIN USER INTENT]")
        print(user_prompt)

        print("\n--------------------------------------------------")
        print("[FOLLOW-UP USER INPUTS]")
        print_follow_ups(follow_up_inputs)

        print("\n--------------------------------------------------")
        print("[AI AGENT REASONING]")
        print_reasoning(reasoning)

        print("\n--------------------------------------------------")
        print("[ACTION SUMMARY]")

        summary_counter = summarize_actions(actions)

        if not summary_counter:
            print("No action detected.")
        else:
            for k, v in summary_counter.items():
                print(f"{k:25} : {v}")

        print("\n--------------------------------------------------")
        print("[NORMALIZED ACTION FLOW]")

        if not actions:
            print("No meaningful action detected.")
        else:
            for idx, action in enumerate(actions, start=1):
                print_action_detail(idx, action)

        print("\n--------------------------------------------------")
        print("[RULE BASE RESULT]")

        if not review_actions:
            print("SAFE")
            print("Reason : Only low-risk actions detected.")

            print("\n--------------------------------------------------")
            print("[GUARD LLM]")
            print("Skipped.")

            print("\n--------------------------------------------------")
            print("[FINAL DECISION]")
            print("ALLOW")
            print("decision reason  : Rule Base detected only low-risk actions.")
            continue

        print("REVIEW_REQUIRED")
        print("Reason : Review-required semantic actions detected.")
        print("Review actions:")

        for action in review_actions:
            print(
                f"- {action['normalized_action']} "
                f"({action['target_class']}) : "
                f"{action['summary']}"
            )

        print("\n--------------------------------------------------")
        print("[GUARD LLM]")

        guard_result = guard_check(
            user_prompt=user_prompt,
            follow_up_inputs=follow_up_inputs,
            reasoning="\n".join(reasoning),
            syscall_summary=[x["summary"] for x in review_actions],
            execve_analysis=review_actions
        )

        label = guard_result["label"]
        reason = guard_result["reason"]
        raw_output = guard_result["raw_output"]

        final_decision = label_to_decision(label)
        decision_reason = decision_reason_from_label(label)

        print("label  :", label)
        print("reason :", reason)
        print("raw output :", raw_output)

        print("\n--------------------------------------------------")
        print("[FINAL DECISION]")
        print(final_decision)
        print("decision reason  :", decision_reason)

        if final_decision == "USER_CONFIRM":
            print("\n[USER CONFIRM REQUIRED]")
            print("This action requires user confirmation because Guard LLM classified it as harmful.")


if __name__ == "__main__":
    run()
