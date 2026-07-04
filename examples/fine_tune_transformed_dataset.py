from llm_recovery.load_llm.load_llm import LoadLLM
from llm_recovery.fine_tuning.lora import LORA
import llm_recovery.constants.constants as constants
from llm_recovery.fine_tuning.examples_dataset import ExamplesDataset
from transformers import set_seed
from datasets import load_dataset
import torch
import numpy as numpy

if __name__ == '__main__':
    # 只在你信任 checkpoint 来源时使用（你自己训练的一般没问题）

    seed = 99125
    set_seed(seed)
    device_map = {"": 0}
    tokenizer, llm = LoadLLM.load_llm(llm_name=constants.LLM.DEEPSEEK_1_5B_QWEN, device_map=device_map) # choose model

    new_data_path = r"D:\RA Project\AI Agent&Cybersecurity paper\updated_data\transformed_dataset_cls_pri_all2preprocessing.json"
    ds_new = load_dataset("json", data_files=new_data_path)
    # ds_new["train"] 里每一行就是一个 dict，抽出 instruction / output 两列
    instructions = [row["instruction"] for row in ds_new["train"]] # ["intruction0", "...", "instructionN"]
    answers = [row["output"] for row in ds_new["train"]]      # ["answer0", "...", "answerN"]


    lora_rank = 64
    lora_alpha = 128
    lora_dropout = 0.05
    llm = LORA.setup_llm_for_fine_tuning(llm=llm, r=lora_rank, lora_alpha=lora_alpha, lora_dropout=lora_dropout)
    dataset = ExamplesDataset(instructions=instructions, answers=answers, tokenizer=tokenizer)
    
    lr = 0.00095  # 0.000095
    per_device_batch_size = 1 # updated
    num_train_epochs = 1
    prompt_logging_frequency = 50
    max_generation_tokens = 500
    logging_steps = 1
    running_average_window = 100
    temperature = 0.6
    save_steps = 50   # 注意lora.py定义了checkpoint存储地址
    save_limit = 3
    gradient_accumulation_steps = 3 # updated
    progress_save_frequency = 10
    # RESUME = "/content/drive/MyDrive/llm_recovery_runs/ds-dt-lora/checkpoint-7750" # checkpoint path
    # RESUME = r"D:\RA Project\AI Agent&Cybersecurity paper\llm_recovery\transformed-dataset-lora\checkpoint-975"  # checkpoint path
    # resume_from_checkpoint=RESUME/None
    LORA.supervised_fine_tuning(llm=llm, dataset=dataset, learning_rate=lr,
                                per_device_train_batch_size=per_device_batch_size,
                                num_train_epochs=num_train_epochs, logging_steps=logging_steps, prompts=instructions,
                                answers=answers,
                                prompt_logging=True,
                                running_average_window=running_average_window,
                                max_generation_tokens=max_generation_tokens,
                                prompt_logging_frequency=prompt_logging_frequency, temperature=temperature,
                                save_steps=save_steps, save_limit=save_limit,
                                gradient_accumulation_steps=gradient_accumulation_steps,
                                progress_save_frequency=progress_save_frequency, seed=seed, resume_from_checkpoint=None) # Checkpoint开关