# src/llm_recovery/evaluation/eval_states_accuracy.py
import json
import torch
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForCausalLM
from peft import PeftModel, PeftConfig
from llm_recovery.evaluation import exact_match_accuracy
from llm_recovery.evaluation.exact_match import REQUIRED_FIELDS
import time
from llm_recovery.evaluation.f1_score import multilabel_f1_from_texts  


def main():
    # 1) Load model (base + LoRA adapter)
    adapter_dir = "/content/drive/MyDrive/Colab Notebooks/llm_recovery_runs/new-lora/checkpoint-250"  # 检测微调后的模型的位置
    # 关键作用：从 adapter_dir 里解析出 LoRA 的超参、任务类型
    # 以及 底座模型名字/路径（peft_cfg.base_model_name_or_path）
    peft_cfg = PeftConfig.from_pretrained(adapter_dir)
    # 根据 底座模型 的名字/路径加载对应的 tokenizer
    tokenizer = AutoTokenizer.from_pretrained(peft_cfg.base_model_name_or_path, use_fast=True)
    
    tokenizer.pad_token = tokenizer.eos_token

    device_map = {"": 0}  # 防止bug
    
    # 加载 底座大模型 
    base = AutoModelForCausalLM.from_pretrained(peft_cfg.base_model_name_or_path, device_map=device_map)
    # 把 LoRA 适配器 挂载/融合到 base 模型上，得到最终用于推理的 model 
    model = PeftModel.from_pretrained(base, adapter_dir)
    print("peft base:", peft_cfg.base_model_name_or_path)
    print("loaded base:", base.config._name_or_path)
    model.eval()

    # 2) Load data
    ds = load_dataset("kimhammar/CSLE-IncidentResponse-V1", data_files="states_examples.json")
    sample = ds["train"][0]
    instructions = sample["instructions"][50_000:50_200]  #采样的数据量
    labels = sample["answers"][50_000:50_200]        #采样的数据量

    preds = []
    total_start = time.time()       # 开始时间  
    with torch.no_grad():
        for i, instr in enumerate(instructions):
            inputs = tokenizer(instr, return_tensors="pt").to(model.device)
            out = model.generate(
                **inputs,
                max_new_tokens=256,
                do_sample=False, #不要采样
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
            text = tokenizer.decode(out[0], skip_special_tokens=True)
            preds.append(text)
            
            if (i + 1) % 10 == 0 or (i + 1) == len(instructions):  #查看进度和时间                                                                                                         
              total_elapsed = time.time() - total_start 
              print(f"Processed {i + 1}/{len(instructions)} in total {total_elapsed:.2f}s", flush=True)
    # 如果 labels 是 dict 而不是 JSON 字符串，需要 json.dumps 把它转成 JSON 格式的字符串 
    label_texts = [json.dumps(l) if isinstance(l, dict) else l for l in labels]
    acc = exact_match_accuracy(preds, label_texts)
    print(f"Exact-match accuracy: {acc:.4f}")
    f1 = multilabel_f1_from_texts(preds, label_texts) # multilabel f1和exact match accuracy需要JSON文件作为参数传入
    print(f"Micro-F1: {f1['micro_f1']:.4f}")
    print(f"Macro-F1: {f1['macro_f1']:.4f}") 
    print("Per-state F1:")
    for i, key in enumerate(REQUIRED_FIELDS):                                                                                                                                      
        print(f"  {key}: {f1['per_label_f1'][i]:.4f}")

if __name__ == "__main__":
    main()