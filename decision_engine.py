# decision_engine.py

from conversation_timeline_parser import build_intent_timeline
from execve_analyzer import analyze_execve
from guard_llm import guard_check
from target_analyzer import policy_decision_for_action


LOG_FOLDER = "./reason-pipeline-results"


def label_to_decision(label):
    if label == "normal":
        return "ALLOW"

    if label == "harmful":
        return "BLOCK"

    if label == "ambiguous":
        return "USER_CONFIRM"

    return "USER_CONFIRM"


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


def apply_policy_override(
    final_decision,
    review_actions
):
    policy_results = []

    for action in review_actions:
        policy_result, policy_reason = policy_decision_for_action(action)

        if policy_result != "allow":
            policy_results.append({
                "policy_result": policy_result,
                "policy_reason": policy_reason,
                "action": action
            })

    for result in policy_results:
        if result["policy_result"] == "block":
            return "BLOCK", result

    for result in policy_results:
        if result["policy_result"] == "confirm":
            if final_decision == "ALLOW":
                return "USER_CONFIRM", result

    return final_decision, None


def summarize_actions(actions):
    counter = {}

    for action in actions:
        key = action["normalized_action"]
        counter[key] = counter.get(key, 0) + 1

    return counter


# ==================================================
# 새로 추가한 부분
# 원본 syscall JSON 정보 출력용
# ==================================================

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
    """
    reason-pipeline-results 안의 raw summary는 보통
    'execve /usr/bin/git /usr/bin/git ...'
    형태라서 action summary와 비교하기 쉽게 정리한다.
    """
    if raw is None:
        return ""

    text = str(raw).strip()

    if text.startswith("execve "):
        text = text[len("execve "):].strip()

    return text


def find_matching_syscall(action, syscalls):
    """
    analyze_execve()가 만든 action과
    원본 reason-pipeline-results의 syscall JSON을 연결한다.

    완벽히 1:1로 안 맞을 수도 있어서 아래 순서로 찾는다.
    1. action summary가 raw summary에 포함되는지 확인
    2. raw summary가 action summary에 포함되는지 확인
    3. argv 문자열이 action summary와 겹치는지 확인
    """

    action_summary = str(action.get("summary", "")).strip()

    if not action_summary:
        return None

    # 1차: summary 기반 매칭
    for syscall in syscalls:
        raw_summary = normalize_raw_summary(syscall.get("summary", ""))

        if not raw_summary:
            continue

        if action_summary in raw_summary:
            return syscall

        if raw_summary in action_summary:
            return syscall

    # 2차: argv 기반 매칭
    for syscall in syscalls:
        argv_text = argv_to_text(syscall.get("argv", []))

        if not argv_text:
            continue

        if action_summary in argv_text:
            return syscall

        if argv_text in action_summary:
            return syscall

    # 3차: 명령어 이름 기반 약한 매칭
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
    """
    action마다 원본 syscall 정보를 붙인다.
    출력하고 싶은 값:
    - agent_name
    - event_id
    - syscall
    - path
    - argv
    - raw_summary
    """

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

        # 기존 코드
        actions = analyze_execve(syscalls)

        # 새로 추가한 코드
        # analyze_execve() 결과에 원본 syscall 정보를 다시 붙인다.
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
            syscall_summary=[
                x["summary"]
                for x in review_actions
            ],
            execve_analysis=review_actions
        )

        label = guard_result["label"]
        reason = guard_result["reason"]
        raw_output = guard_result["raw_output"]

        llm_decision = label_to_decision(label)

        final_decision, policy_override = apply_policy_override(
            llm_decision,
            review_actions
        )

        print("label  :", label)
        print("reason :", reason)
        print("raw output :", raw_output)

        if policy_override:
            print("\n--------------------------------------------------")
            print("[POLICY OVERRIDE]")
            print("policy result :", policy_override["policy_result"])
            print("reason        :", policy_override["policy_reason"])
            print("action        :", policy_override["action"]["summary"])
            print("target class  :", policy_override["action"]["target_class"])

        print("\n--------------------------------------------------")
        print("[FINAL DECISION]")
        print(final_decision)

        if final_decision == "BLOCK":
            print("\n[RE-REASON REQUEST]")
            print("The previous action was blocked by policy.")
            print("Generate a safer action aligned with the user's request.")

        elif final_decision == "USER_CONFIRM":
            print("\n[USER CONFIRM REQUIRED]")
            print("This action requires user confirmation.")


if __name__ == "__main__":
    run()