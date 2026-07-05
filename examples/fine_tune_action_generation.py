from datasets import load_dataset
from transformers import set_seed

import llm_recovery.constants.constants as constants
from llm_recovery.fine_tuning.examples_dataset import ExamplesDataset
from llm_recovery.fine_tuning.lora import LORA
from llm_recovery.load_llm.load_llm import LoadLLM


if __name__ == "__main__":
    seed = 99125
    set_seed(seed)
    device_map = {"": 0}
    tokenizer, llm = LoadLLM.load_llm(
        llm_name=constants.LLM.DEEPSEEK_14B_QWEN,
        device_map=device_map,
    )

    ds = load_dataset(
        "kimhammar/CSLE-IncidentResponse-V1",
        data_files="action_examples.json",
    )
    train = ds["train"][0]
    instructions = train["instructions"]
    answers = train["answers"]

    lora_rank = 64
    lora_alpha = 128
    lora_dropout = 0.05
    llm = LORA.setup_llm_for_fine_tuning(
        llm=llm,
        r=lora_rank,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
    )
    dataset = ExamplesDataset(
        instructions=instructions,
        answers=answers,
        tokenizer=tokenizer,
    )

    lr = 0.00095
    per_device_batch_size = 1
    num_train_epochs = 1
    prompt_logging_frequency = 25
    max_generation_tokens = 3000
    logging_steps = 1
    running_average_window = 100
    temperature = 0.6
    save_steps = 50
    save_limit = 3
    gradient_accumulation_steps = 32
    progress_save_frequency = 10

    # Set this to a checkpoint path to resume training.
    resume_from_checkpoint = None
    LORA.supervised_fine_tuning(
        llm=llm,
        dataset=dataset,
        learning_rate=lr,
        per_device_train_batch_size=per_device_batch_size,
        num_train_epochs=num_train_epochs,
        logging_steps=logging_steps,
        prompts=instructions,
        answers=answers,
        prompt_logging=True,
        running_average_window=running_average_window,
        max_generation_tokens=max_generation_tokens,
        prompt_logging_frequency=prompt_logging_frequency,
        temperature=temperature,
        save_steps=save_steps,
        save_limit=save_limit,
        gradient_accumulation_steps=gradient_accumulation_steps,
        progress_save_frequency=progress_save_frequency,
        seed=seed,
        resume_from_checkpoint=resume_from_checkpoint,
    )
