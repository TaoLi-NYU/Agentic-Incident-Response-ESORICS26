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
    RESUME_ADAPTER = "/content/drive/MyDrive/Colab Notebooks/llm_recovery_runs/new-lora/checkpoint-250" # checkpoint
    tokenizer, llm = LoadLLM.load_llm(llm_name=constants.LLM.DEEPSEEK_14B_QWEN, device_map=device_map) # choose model
    llm = PeftModel.from_pretrained(llm, RESUME_ADAPTER, is_trainable=True) # keep LORA weights and set trainable

    """ 
        [
            {
                "instructions": ["instruction0", "...", "instructionN"],
                "answers":      ["answer0", "...", "answerN"]
            }
        ]
    """
    ds_states = load_dataset("kimhammar/CSLE-IncidentResponse-V1", data_files="states_examples.json")
    train_states = ds_states["train"][0]                
    instructions_states = train_states["instructions"]  # ["intruction0", "...", "instructionN"]
    answers_states = train_states["answers"]            # ["answer0", "...", "answerN"]

    # load_dataset("json", data_files=...) 会默认生成一个 DatasetDict，分割名通常就是 "train"，所以 ds_new["train"] 是存在的
    # 会看到类似：DatasetDict({ train: Dataset(...) })
    # 10868条data points
    
    new_data_path = r"/content/drive/MyDrive/transformed_dataset_cls_pri_all2preprocessing.json"
    ds_new = load_dataset("json", data_files=new_data_path)
    
    
    # ds_new["train"] 里每一行就是一个 dict，抽出 instruction / output 两列
    instructions_new = [row["instruction"] for row in ds_new["train"]] # ["intruction0", "...", "instructionN"]
    answers_new = [row["output"] for row in ds_new["train"]]           # ["answer0", "...", "answerN"]

    target_total = 21736 # 50% vs 50% 
    per_dataset = min(target_total // 2, len(instructions_states), len(instructions_new))
    instructions = instructions_states[:per_dataset] + instructions_new[:per_dataset] # 这一步只是“拼在一起”：前半来自 states，后半来自 new
    answers = answers_states[:per_dataset] + answers_new[:per_dataset]

    """
    zip 就是把多个可迭代对象 (list/tuple/string…) 按“同一位置”打包成一组一组的元组
    a = [1, 2, 3]   b = ["x", "y", "z"]     list(zip(a, b))
    [(1, 'x'), (2, 'y'), (3, 'z')]
    """
    combined = list(zip(instructions, answers))
    rng = random.Random(seed)
    rng.shuffle(combined) # 打乱顺序
    if combined:
        instructions, answers = zip(*combined) # 解压得到的是 tuple
        instructions = list(instructions)
        answers = list(answers)
    else:
        instructions, answers = [], []


    dataset = ExamplesDataset(instructions=instructions, answers=answers, tokenizer=tokenizer)
    
    lr = 0.00095  # 0.000095
    per_device_batch_size = 1 # updated
    num_train_epochs = 1
    prompt_logging_frequency = 25 # To observe training result more frequent
    max_generation_tokens = 500 # according labels length
    logging_steps = 1
    running_average_window = 100
    temperature = 0.6
    save_steps = 50   # 注意lora.py定义了checkpoint存储地址
    save_limit = 3
    gradient_accumulation_steps = 32 # updated
    progress_save_frequency = 10
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
