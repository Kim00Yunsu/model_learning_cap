from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
    DataCollatorForLanguageModeling
)

from peft import (
    LoraConfig,
    get_peft_model
)

from datasets import load_dataset

import torch


# =========================
# 모델 이름
# =========================

MODEL_NAME = "Qwen/Qwen3.5-0.8B"

# =========================
# tokenizer
# =========================

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME,
    trust_remote_code=True
)

tokenizer.pad_token = tokenizer.eos_token



# =========================
# 모델 로드
# =========================

model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    device_map="auto",
    torch_dtype=torch.float16,
    trust_remote_code=True
)

# =========================
# LoRA 설정
# =========================

lora_config = LoraConfig(
    r=8,
    lora_alpha=16,
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",

    target_modules=[
        "q_proj",
        "k_proj",
        "v_proj",
        "o_proj"
    ]
)

# =========================
# LoRA 적용
# =========================

model = get_peft_model(
    model,
    lora_config
)

model.print_trainable_parameters()

# =========================
# dataset load
# =========================

dataset = load_dataset(
    "json",
    data_files="dataset/final_guard_train.jsonl"
)

train_dataset = dataset["train"]

# =========================
# tokenize
# =========================

def tokenize_function(example):

    return tokenizer(
        example["text"],
        truncation=True,
        max_length=256,
        padding="max_length"
    )

tokenized_dataset = train_dataset.map(
    tokenize_function,
    batched=True
)

# =========================
# training args
# =========================

training_args = TrainingArguments(
    output_dir="./guard-lora",

    per_device_train_batch_size=1,

    gradient_accumulation_steps=4,

    learning_rate=2e-4,

    num_train_epochs=3,

    logging_steps=10,

    save_steps=50,

    fp16=True,

    optim="adamw_torch",

    report_to="none"
)

# =========================
# trainer
# =========================

trainer = Trainer(
    model=model,

    args=training_args,

    train_dataset=tokenized_dataset,

    data_collator=DataCollatorForLanguageModeling(
        tokenizer=tokenizer,
        mlm=False
    )
)

# =========================
# train
# =========================

trainer.train()

# =========================
# save
# =========================

model.save_pretrained("./guard-lora")

tokenizer.save_pretrained("./guard-lora")

print("\n====================")
print("TRAIN FINISHED")
print("====================")