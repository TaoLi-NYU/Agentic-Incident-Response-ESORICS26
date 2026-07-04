from llm_recovery.load_llm.load_llm import LoadLLM
from llm_recovery.fine_tuning.lora import LORA
import llm_recovery.constants.constants as constants
from llm_recovery.fine_tuning.examples_dataset import ExamplesDataset
from transformers import set_seed
from datasets import load_dataset
import random
from peft import PeftModel


if __name__ == '__main__':
    seed = 99125
    set_seed(seed)
    device_map = {"": 0}

    # Load base model, then load previous LoRA adapter weights as initialization.
    RESUME_ADAPTER = "/content/drive/MyDrive/llm_recovery_runs-continue-twodatasets/checkpoint-1050"
    tokenizer, llm = LoadLLM.load_llm(
        llm_name=constants.LLM.DEEPSEEK_14B_QWEN,
        device_map=device_map,
    )
    llm = PeftModel.from_pretrained(llm, RESUME_ADAPTER, is_trainable=True)

    # Dataset 1: states_examples.json
    ds_states = load_dataset(
        "kimhammar/CSLE-IncidentResponse-V1", data_files="states_examples.json"
    )
    train_states = ds_states["train"][0]
    instructions_states = train_states["instructions"]
    answers_states = train_states["answers"]

    # Dataset 2: action_examples.json
    ds_actions = load_dataset(
        "kimhammar/CSLE-IncidentResponse-V1", data_files="action_examples.json"
    )
    train_actions = ds_actions["train"][0]
    instructions_actions = train_actions["instructions"]
    answers_actions = train_actions["answers"]

    # Dataset 3: incident_examples.json (new)
    ds_incident = load_dataset(
        "kimhammar/CSLE-IncidentResponse-V1", data_files="incident_examples.json"
    )
    train_incident = ds_incident["train"][0]
    instructions_incident = train_incident["instructions"]
    answers_incident = train_incident["answers"]

    # Dataset 4: local JSON dataset
    new_data_path = r"/content/drive/MyDrive/transformed_dataset_cls_pri_all2preprocessing.json"
    ds_new = load_dataset("json", data_files=new_data_path)
    instructions_new = [row["instruction"] for row in ds_new["train"]]
    answers_new = [row["output"] for row in ds_new["train"]]

    states_target = 5000
    new_target = 5000
    actions_target = 5000
    incident_target = 15000

    states_n = min(states_target, len(instructions_states), len(answers_states))
    new_n = min(new_target, len(instructions_new), len(answers_new))
    actions_n = min(actions_target, len(instructions_actions), len(answers_actions))
    incident_n = min(incident_target, len(instructions_incident), len(answers_incident))

    instructions = (
        instructions_states[:states_n]
        + instructions_new[:new_n]
        + instructions_actions[:actions_n]
        + instructions_incident[:incident_n]
    )
    answers = (
        answers_states[:states_n]
        + answers_new[:new_n]
        + answers_actions[:actions_n]
        + answers_incident[:incident_n]
    )

    print(f"states_examples: {states_n}")
    print(f"new_data: {new_n}")
    print(f"action_examples: {actions_n}")
    print(f"incident_examples: {incident_n}")

    combined = list(zip(instructions, answers))
    rng = random.Random(seed)
    rng.shuffle(combined)
    if combined:
        instructions, answers = zip(*combined)
        instructions = list(instructions)
        answers = list(answers)
    else:
        instructions, answers = [], []

    dataset = ExamplesDataset(instructions=instructions, answers=answers, tokenizer=tokenizer)

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
        resume_from_checkpoint=None,
    )
