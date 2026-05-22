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

        safe_actions, review_actions = split_actions(actions)

        print("\n\n==================================================")
        print(f"INTENT {intent['intent_id']}")
        print("==================================================")

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
                print(f"\n[ACTION #{idx}]")
                print("summary           :", action["summary"])
                print("meaning           :", action["meaning"])
                print("normalized action :", action["normalized_action"])
                print("target class      :", action["target_class"])
                print("rule result       :", action["rule_result"])

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