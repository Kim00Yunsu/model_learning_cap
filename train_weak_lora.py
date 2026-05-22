# train_weak_lora.py

import os
import json
import torch

from datasets import Dataset

from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    TrainingArguments,
    Trainer,
)

from peft import (
    LoraConfig,
    get_peft_model,
)

# ==========================================
# model
# ==========================================

BASE_MODEL = "Qwen/Qwen3.5-0.8B"

OUTPUT_DIR = "outputs/qwen3_5_0_8b_weak_lora"

DATASET_PATH = "dataset/final_guard_train.jsonl"

# ==========================================
# tokenizer
# ==========================================

tokenizer = AutoTokenizer.from_pretrained(
    BASE_MODEL
)

if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# ==========================================
# model
# ==========================================

model = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL,
    dtype=torch.float16
    if torch.backends.mps.is_available()
    else torch.float32,
    device_map="auto",
)

model.config.pad_token_id = tokenizer.pad_token_id

# ==========================================
# VERY WEAK LoRA
# ==========================================

lora_config = LoraConfig(
    r=2,
    lora_alpha=4,
    lora_dropout=0.1,
    bias="none",
    task_type="CAUSAL_LM",

    target_modules=[
        "q_proj",
        "k_proj",
    ],
)

model = get_peft_model(
    model,
    lora_config
)

model.print_trainable_parameters()

# ==========================================
# load dataset
# ==========================================

samples = []

with open(DATASET_PATH, "r", encoding="utf-8") as f:

    for line in f:

        line = line.strip()

        if not line:
            continue

        data = json.loads(line)

        text = data["text"]

        samples.append({
            "text": text
        })

print(f"\nLoaded dataset size: {len(samples)}")

dataset = Dataset.from_list(samples)

# ==========================================
# tokenize
# ==========================================

MAX_LENGTH = 256

def tokenize_function(example):

    result = tokenizer(
        example["text"],
        truncation=True,
        max_length=MAX_LENGTH,
        padding="max_length",
    )

    result["labels"] = result["input_ids"].copy()

    return result

tokenized_dataset = dataset.map(
    tokenize_function
)

# ==========================================
# training args
# ==========================================

training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,

    per_device_train_batch_size=1,

    gradient_accumulation_steps=4,

    learning_rate=5e-6,

    num_train_epochs=1,

    logging_steps=1,

    save_strategy="epoch",

    fp16=False,

    bf16=False,

    report_to="none",

    remove_unused_columns=False,
)

# ==========================================
# trainer
# ==========================================

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset,
)

# ==========================================
# train
# ==========================================

trainer.train()

# ==========================================
# save
# ==========================================

model.save_pretrained(
    OUTPUT_DIR
)

tokenizer.save_pretrained(
    OUTPUT_DIR
)

print("\n====================")
print("TRAIN DONE")
print("====================")