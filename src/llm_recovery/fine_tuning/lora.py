from typing import Union, List, Optional
from transformers import PreTrainedModel, Trainer, TrainingArguments, PrinterCallback, ProgressCallback
# Trainer / TrainingArguments：transformers 自带的训练框架。
# PrinterCallback, ProgressCallback: Trainer 默认的打印/进度条回调，后面会被移除
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from llm_recovery.decision_transformer.dt_dataset import DTDataset
from llm_recovery.fine_tuning.examples_dataset import ExamplesDataset
from llm_recovery.fine_tuning.post_think_dataset import PostThinkDataset
import llm_recovery.constants.constants as constants
from llm_recovery.fine_tuning.logging_callback import LoggingCallback
# LoggingCallback：项目自定义的训练日志回调
from peft import TaskType


class LORA:
    """
    Class with utility functions for fine-tuning with LORA
    """

    @staticmethod
    def setup_llm_for_fine_tuning(llm: PreTrainedModel, r: int = 8, lora_alpha: int = 32,
                                  lora_dropout: float = 0.05, use_quantization: bool = True):
        """
        Sets up a given LLM for fine-tuning with LORA

        :param llm: the LLM to fine-tune
        :param r: The LORA dimension, i.e.,  the rank
        :param lora_alpha: The alpha parameter for Lora scaling.
        :param lora_dropout: The dropout probability for Lora layers.
        :return: the LLM prepared for fine-tuning
        """
        if use_quantization:
            llm = prepare_model_for_kbit_training(llm)
        lora_cfg = LoraConfig(r=r, lora_alpha=lora_alpha, lora_dropout=lora_dropout,
                              bias="none", task_type=TaskType.CAUSAL_LM)
        llm_for_fine_tuning = get_peft_model(llm, lora_cfg)
        """
        prepare_model_for_kbit_training 是 PEFT 提供的工具：
        权重是 量化过的 (4bit)，本身不适合直接更新(离散，误差大)
        
        LoRA 的思路是：
        冻结原始权重，
        只训练额外加的低秩矩阵 (LoRA adapter)
        但在具体实现上，还有一堆细节要处理，比如：
        哪些层需要保持高精度 (如 LayerNorm)
        怎么确保不会对量化权重误更新 requires_grad=True
        和 bitsandbytes 的 4bit 模块兼容；
        和梯度检查点 / use_cache 等行为相容。
        这些“脏活累活”就都塞进了 prepare_model_for_kbit_training 里面
        对你来说：理解为「把量化模型变成适合挂 LoRA 的版本」

        bias 通常有三种策略(PEFT 里的配置):
        bias="none"
        不给 bias 加新参数, 也不去训练原来的 bias
        只有 LoRA 的 A、B 是可训练的（普通最省参数的设定）
        bias="lora_only":
        只训练 LoRA 的 bias(很少用)
        bias="all":
        原模型的 bias 也解冻，让它参与训练（参数会增多）
        bias="none": LoRA 不单独学习 bias
        这些线性层在代码里一般是：
        nn.Linear(in_features, out_features, bias=True)
        也就是每个 Linear 都有一个自己的 bias: b_q, b_k, b_v, b_o, b_up, b_down ……

        线性层的代码一般是: 
        nn.Linear(in_features, out_features, bias=True)

        task_type=TaskType.CAUSAL_LM
        告诉 PEFT: 这是一个因果语言建模任务(GPT 类模型)
        它会自动知道要在 attention 的哪些投影上插 LoRA(如 q_proj、v_proj),以及在前馈网络的哪些投影上插 LoRA(如 up_proj、down_proj)
        
        get_peft_model 会:
        冻结原始权重(不再训练)
        在指定层(比如注意力的 Wq/Wv)上插入 LoRA 模块；
        只让 LoRA 模块的参数 requires_grad=True。
        返回的 llm_for_fine_tuning
        是“原模型 + LoRA 插件”的组合，你后面训练时真正更新的是这些 LoRA 权重
        """
        if use_quantization:
            llm.gradient_checkpointing_enable()
        """
        Gradient checkpointing: 把中间激活图的一部分丢掉,反向再重算,换算力来省显存
        对大模型 + LoRA 很常见，尤其是你这类显存紧张的环境。
        对你来说：记成「再开一层显存节省」

        激活图:
        [batch, seq_len, hidden_dim]
        = [一次喂几句, 每句有几个 token(经过 pad_sequence 之后), 每个 token 用多少维向量表示(也叫隐藏维度、embedding 维度)]
        vocab_size(词表大小,含有多少个不同 token) 
        
        词表大小 vocab_size = 5, 隐藏维度 hidden_dim = 3,
        # embedding_matrix[token_id] = 这个 token 对应的 3 维向量
        embedding_matrix = [
            [0.1, 0.0, 0.2],   # token 0 的向量
            [0.0, 0.5, 0.3],   # token 1 的向量
            [0.2, 0.1, 0.4],   # token 2 的向量
            [0.7, 0.8, 0.9],   # token 3 的向量
            [0.5, 0.4, 0.6],   # token 4 的向量
        ]

        现在你就能理解这句话了：
        Gradient checkpointing: 把中间激活图的一部分丢掉, 反向再重算, 换算力来省显存
        更具体一点：
        
        普通训练(不用 checkpoint)
        Forward 时，每一层都算一次，然后把这一层的激活留住：
        layer0: 保存 h0
        layer1: 保存 h1
        layer2: 保存 h2
        ...
        layerN: 保存 hN
        Backward 时，从最后一层往前，依次用这些激活来算梯度。
        显存开销：要同时保存所有层的激活

        layer是一层神经网络还是一个大的block ?
        当然理论上你可以自己划分：
        把 block 里面的 attention / MLP 各算一层；
        或者把两三个 block 当成一个大层；
        但在 LLM 实现里, “layer = 一个 Transformer block”是最常见写法
        
        用 gradient checkpointing 时：
        想象把 N 层网络分成几个“小段”，只在“段与段的边界”做 checkpoint:
        Forward 时:
        对一段内的中间层不存激活 (算完就丢)
        只把某些关键节点(checkpoint)存下来
        Backward 时：
        需要这个段内部的激活了
        → 从最近的 checkpoint 重新跑一遍 forward, 临时算出这几层的激活, 再算梯度
        算完梯度，这一小段的激活又可以丢掉。
        这样：
        显存里只需要存“部分层”的激活(checkpoint 所在位置)
        代价是：反向传播时，会重复做一些 forward 计算(多花时间)

        """
        
        
        """
        每个 nn.Module(包括大模型)都有: model.parameters() 会返回模型中所有参数(权重)的迭代器
        numel() 返回这个张量中元素的总个数 (number of elements)
        生成器表达式 p.numel() for p in trainable_params

        llm_for_fine_tuning: 外面套了一层 PEFT 容器
        """
        trainable_params = [p for p in llm_for_fine_tuning.parameters() if p.requires_grad]
        total_trainable = sum(p.numel() for p in trainable_params)
        print(f"Trainable parameters: {total_trainable}")
        return llm_for_fine_tuning
    

    @staticmethod
    def supervised_fine_tuning(llm: PreTrainedModel, dataset: Union[DTDataset, ExamplesDataset, PostThinkDataset],
                               output_dir: str = "transformed-updated-dataset(preprocessing)-lora",
                               learning_rate: float = 5e-5, logging_steps: int = 1,
                               per_device_train_batch_size: int = 1, num_train_epochs: int = 3,
                               prompt_logging: bool = False, prompts: Optional[List[str]] = None,
                               answers: Optional[List[str]] = None,
                               max_generation_tokens: int = 32,
                               running_average_window: int = 100, prompt_logging_frequency: int = 1,
                               temperature: float = 0.7, save_steps: int = 100, save_limit: int = 2,
                               gradient_accumulation_steps: int = 1, progress_save_frequency: int = 1,
                               seed: int = 91501, resume_from_checkpoint: Optional[str] = None) -> None:
        """
        output_dir: str = "ds-dt-lora"
        是什么：训练输出目录名，默认 "ds-dt-lora"。
        用来干嘛：保存：
        adapter 权重 (LoRA/XLora 的权重)
        训练日志 (如 trainer_state.json)
        最后或中间 checkpoint (checkpoint-xxx)

        logging_steps: int = 1
        是什么：多少步打印/记录一次日志

        prompt_logging: bool = False
        是什么：是否在训练时“额外把 prompt 打印/记录下来”
        用来干嘛：
        True 时，可能在 logging 里把当前训练样本对应的 prompt 文本打印出来 (方便你检查数据是否正确、有没有奇怪的 tokenization、prompt 格式是否符合论文里的设定)
        False 时，不记录 prompt, 只记录 loss、steps 等，更省日志空间、更安全 (避免泄露敏感数据)

        prompt_logging_frequency: int = 1
        和前面的 logging_steps 有点像，但专门管“打印 prompt (和对应输出)多频繁”。
        直觉：隔多少个训练 step, 打印/记录一次“示例 prompt + 模型生成”的日志。

        running_average_window: int = 100
        直觉：用来平滑指标的“滑动窗口大小”。
        常见玩法：
        例如每一步都有一个 train_loss, 会维护一个“最近 N 步的平均 loss”

        save_steps: int = 100
        直觉：每多少训练 step 存一个 checkpoint

        save_limit: int = 2
        直觉：最多保留多少个最近的 checkpoint
        
        """
        """
        Performs supervised fine-tuning of a given llm based on a given dataset

        :param llm: The LLM to fine-tune
        :param dataset: the dataset to use for the fine-tuning
        :param output_dir: The output directory to save the trained weights
        :param learning_rate: The learning rate to use for the fine-tuning
        :param logging_steps: The number of steps to logging the fine-tuning
        :param per_device_train_batch_size: The number of samples to use per device for fine-tuning
        :param prompt_logging: Boolean flag indicating whether to log test-prompts during training
        :param prompts: The prompts to use for prompt logging
        :param answers: The prompts to use for prompt logging
        :param max_generation_tokens: The maximum number of tokens to generate for prompt logging
        :param running_average_window: length of the window to compute running averages
        :param prompt_logging_frequency: frequency of prompt logging
        :param temperature: controls the randomness of the LLM outputs
        :param save_steps: controls how frequently to checkpoint the model
        :param save_limit: controls the maximum number of saved copies of the model
        :param gradient_accumulation_steps: how many gradients to accumulate before updating model
        :param use_quantization: boolean flag indicating whether quantization should be used
        :param progress_save_frequency: frequency of saving training progress to disk
        :param seed: the random seed for reproducibility
        :return: None
        """
        """
        per_device_train_batch_size = 5
        gradient_accumulation_steps = 16
        在 单卡 情况下含义是：
        每一步 trainer 从 DataLoader 里拿 5 条样本，在 GPU 上算一次前向 + 反向，得到梯度；
        但 不立刻更新参数，而是把梯度累积起来；
        连续累积 16 次之后（相当于看了 5 * 16 = 80 条样本），再做一次真正的 optimizer.step() 更新
        
        单 GPU 时：
        per_device_train_batch_size = “显存一次能装下的样本数”；
        有效 batch size = per_device_train_batch_size * gradient_accumulation_steps。
        多 GPU 时：
        每块卡上都是 per_device_train_batch_size
        总有效 batch = per_device_train_batch_size * gradient_accumulation_steps * GPU数
        """
        if prompts is None:
            prompts = []
        if answers is None:
            answers = []
        gen_kwargs = dict(max_new_tokens=max_generation_tokens, temperature=temperature, do_sample=True)
        """
        generation keyword arguments → “传给 model.generate(...) 的关键字参数字典
        max_new_tokens: 最多生成多少 token
        temperature: 采样温度, 越高越随机
        do_sample=True: 用采样而不是贪心
        {"hello": 0.5, "hi": 0.3, "hey": 0.15, "<unk>": 0.05}
        采样: 按概率随机选, 稳定, 缺乏创造性
        贪心: 直接选概率最高的 "hello"
        """

        args = TrainingArguments(
            output_dir=output_dir, bf16=True,
            per_device_train_batch_size=per_device_train_batch_size, num_train_epochs=num_train_epochs,
            learning_rate=learning_rate, logging_steps=logging_steps,
            save_strategy=constants.LORA.SAVE_STRATEGY_STEPS, save_steps=save_steps,
            save_total_limit=save_limit, gradient_accumulation_steps=gradient_accumulation_steps, seed=seed)
        
        """
        output_dir: 保存 checkpoints 的目录。
        bf16=True: 训练时用 bfloat16(要你的硬件支持;新显卡一般可以)
        logging_steps: 每多少步 log 一次训练信息。
        save_strategy="steps"：按照步数来 checkpoint。
        save_steps: 每 N 步保存一次模型。
        save_total_limit: 最多保留多少个 checkpoint, 超过会删旧的。
        gradient_accumulation_steps: 控制“多少个小 batch 累积成一个大梯度更新”。
        seed:随机种子, 保证可复现。
        
        每处理一个 batch 并更新一次参数 → 叫做 1 个 global step
        global_step 一般就是大家说的 “step”
        """
        callback = LoggingCallback(prompts=prompts, tokenizer=dataset.tokenizer, window=running_average_window,
                                   gen_kwargs=gen_kwargs, dataset=dataset,
                                   prompt_logging=prompt_logging, prompt_logging_frequency=prompt_logging_frequency,
                                   answers=answers, progress_save_frequency=progress_save_frequency, seed=seed)
        """
        LoggingCallback 是项目自己写的，主要负责：
        每隔若干 step, 用当前模型对一组 prompts 做生成；
        记录这些输出 & loss 的滑动平均 (window)
        把训练过程的指标/样例保存到磁盘 (progress_save_frequency)
        如果给了 answers, 可能会对生成结果和真实答案做一些比较。
        你可以简单理解为：这是比默认 Trainer 打 log 更“懂你这个任务”的日志系统
        """
        trainer = Trainer(model=llm, args=args, train_dataset=dataset, data_collator=dataset.collate,
                          callbacks=[callback])
        trainer.remove_callback(PrinterCallback)
        trainer.remove_callback(ProgressCallback)
        trainer.train(resume_from_checkpoint=resume_from_checkpoint)
        trainer.save_model(output_dir=output_dir)
