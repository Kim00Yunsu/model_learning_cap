import json
from collections import Counter

DATASET_PATH = "dataset/final_guard_train.jsonl"

counter = Counter()

with open(DATASET_PATH, "r", encoding="utf-8") as f:

    for line in f:

        data = json.loads(line)

        text = data["text"]

        if "### Answer:\nappropriate" in text:
            counter["appropriate"] += 1

        elif "### Answer:\ninappropriate" in text:
            counter["inappropriate"] += 1

        elif "### Answer:\nuncertain" in text:
            counter["uncertain"] += 1

print("\n===================")
print("LABEL DISTRIBUTION")
print("===================")

total = sum(counter.values())

for k, v in counter.items():

    ratio = (v / total) * 100

    print(f"{k:15} : {v:4} ({ratio:.2f}%)")