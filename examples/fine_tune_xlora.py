from llm_recovery.load_llm.load_llm import LoadLLM
from llm_recovery.fine_tuning.lora import LORA
from llm_recovery.fine_tuning.xlora import XLORA
import llm_recovery.constants.constants as constants
from llm_recovery.fine_tuning.examples_dataset import ExamplesDataset
from transformers import set_seed
from datasets import load_dataset

if __name__ == '__main__':
    seed = 99125
    set_seed(seed)
    device_map = {"": 0}

    # 1. 加载 base LLM（一定要和你训练 ds-dt-lora 时用的 base 模型一致）
    tokenizer, base_llm = LoadLLM.load_llm(llm_name=constants.LLM.DEEPSEEK_1_5B_QWEN, device_map=device_map)

    # 关键一行：XLora 要求 use_cache=False  不支持 KV 缓存 ★★★
    base_llm.config.use_cache = False

    # 2. 加载数据
    dataset = load_dataset("kimhammar/CSLE-IncidentResponse-V1", data_files="examples_16_june.json")
    instructions = dataset["train"]["instructions"][0]
    answers = dataset["train"]["answers"][0]

    # 3. 把你那三个 LoRA checkpoint 当作 XLora 的 experts
    adapters = {
            "0": r"D:\RA Project\AI Agent&Cybersecurity paper\llm_recovery\ds-dt-lora\checkpoint-175",
            "1": r"D:\RA Project\AI Agent&Cybersecurity paper\llm_recovery\ds-dt-lora\checkpoint-200",
            "2": r"D:\RA Project\AI Agent&Cybersecurity paper\llm_recovery\ds-dt-lora\checkpoint-225",
        }

    # 4. 用 XLORA 组合 base_llm + 多个 LoRA 专家
    xlora_llm = XLORA.setup_llm_for_fine_tuning(
        llm=base_llm,
        adapters=adapters,
        use_quantization=False,          # 和之前 LoRA 一样用 k-bit 训练  （解决报错）
        xlora_depth=1,                  # 先用最简单的线性 gate
        layerwise_scalings=False,       # 不搞每层单独一套权重，先共享,优点参数少,缺点所有层都用同一套混合比例，不能体现“不同层喜欢不同专家” 这种细粒度结构
        softmax_temperature=1.0,
        top_k_lora=None,                # Dense mixture；如果想只激活 2 个专家，就改成 top_k_lora=2
        use_trainable_adapters=False,   # 只训练 gating 网络，LoRA 专家冻结
        global_scaling_weight=1.0,
    )
    dataset = ExamplesDataset(instructions=instructions, answers=answers, tokenizer=tokenizer)
    lr = 0.00095
    per_device_batch_size = 1 # 5
    num_train_epochs = 1 # 2
    prompt_logging_frequency = 50
    max_generation_tokens = 1024 # 6000
    logging_steps = 1
    running_average_window = 100
    temperature = 0.6
    save_steps = 25
    save_limit = 3
    gradient_accumulation_steps = 1 # 16
    progress_save_frequency = 10
    XLORA.supervised_fine_tuning(llm=xlora_llm, dataset=dataset, learning_rate=lr,
                                per_device_train_batch_size=per_device_batch_size,
                                num_train_epochs=num_train_epochs, logging_steps=logging_steps, prompts=instructions,
                                answers=answers,
                                prompt_logging=True,
                                running_average_window=running_average_window,
                                max_generation_tokens=max_generation_tokens,
                                prompt_logging_frequency=prompt_logging_frequency, temperature=temperature,
                                save_steps=save_steps, save_limit=save_limit,
                                gradient_accumulation_steps=gradient_accumulation_steps,
                                progress_save_frequency=progress_save_frequency, seed=seed)