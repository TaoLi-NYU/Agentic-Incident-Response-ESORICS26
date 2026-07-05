import random
import threading

import torch
from datasets import load_dataset
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, TextIteratorStreamer


BASE_MODEL_ID = "deepseek-ai/DeepSeek-R1-Distill-Qwen-14B"
ADAPTER_MODEL_ID = "GYR1-determine/llmagent4incident-response"


if __name__ == "__main__":
    if not torch.cuda.is_available():
        raise RuntimeError("A CUDA-capable GPU is required to run this 14B model.")

    base_model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        dtype=torch.float16,
        device_map="auto",
    )
    model = PeftModel.from_pretrained(base_model, ADAPTER_MODEL_ID)
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID)

    dataset = load_dataset(
        "kimhammar/CSLE-IncidentResponse-V1",
        data_files="examples_16_june.json",
    )
    instructions = dataset["train"]["instructions"][0]

    model.eval()
    instruction = random.choice(instructions)
    input_device = model.get_input_embeddings().weight.device
    inputs = tokenizer(instruction, return_tensors="pt").to(input_device)

    generation_kwargs = {
        **inputs,
        "max_new_tokens": 6000,
        "temperature": 0.8,
        "do_sample": True,
    }
    streamer = TextIteratorStreamer(
        tokenizer,
        skip_special_tokens=True,
        skip_prompt=True,
    )
    generation_thread = threading.Thread(
        target=model.generate,
        kwargs={**generation_kwargs, "streamer": streamer},
    )
    generation_thread.start()

    for new_text in streamer:
        print(new_text, end="", flush=True)

    generation_thread.join()
