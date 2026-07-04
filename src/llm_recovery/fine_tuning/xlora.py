from typing import Union, List, Optional, Dict
from transformers import PreTrainedModel, Trainer, TrainingArguments, PrinterCallback, ProgressCallback
# Trainer / TrainingArguments：transformers 自带的训练框架。
# PrinterCallback, ProgressCallback: Trainer 默认的打印/进度条回调，后面会被移除
from peft import XLoraConfig, LoraConfig, get_peft_model, prepare_model_for_kbit_training
from llm_recovery.decision_transformer.dt_dataset import DTDataset
from llm_recovery.fine_tuning.examples_dataset import ExamplesDataset
from llm_recovery.fine_tuning.post_think_dataset import PostThinkDataset
import llm_recovery.constants.constants as constants
from llm_recovery.fine_tuning.logging_callback import LoggingCallback
# LoggingCallback：项目自定义的训练日志回调
from peft import TaskType

"""
LoRA = 一个 LoRA 适配器；
XLoRA = 一堆 LoRA 适配器 + 一个“门控网络”学着给每个样本/每个 token 动态分配权重的 Mixture-of-LoRA-Experts.
"""

class XLORA:
    """
    Utilities for fine-tuning with X-LoRA (Mixture of LoRA experts)
    """

    @staticmethod
    def setup_llm_for_fine_tuning(
        llm: PreTrainedModel,
        adapters: Dict[str, str],           # 关键：名字 -> LoRA checkpoint 路径
        use_quantization: bool = False,     # 是否用 k-bit 量化模型
        xlora_depth: int = 1,
        layerwise_scalings: bool = False,
        softmax_temperature: float = 1.0,
        top_k_lora: Optional[int] = None,  # 不用稀疏就保持 None
        use_trainable_adapters: bool = False, # False(默认):只训练门控网络，LoRA专家本身是冻结的: True :门控+各 LoRA adapter 一起训练。
        global_scaling_weight: float = 1.0,
    ) -> PreTrainedModel:
        """
        构建 X-LoRA 模型:base model + 多个 LoRA 专家 + gating 网络。默认：只训练 gating (use_trainable_adapters=False)
        """
        if use_quantization:        # 这一步是为了 k-bit；
            llm = prepare_model_for_kbit_training(llm) # 只有在“基座已经是 4bit/8bit 量化”时才有意义

        hidden_size = llm.config.hidden_size
        xlora_cfg = XLoraConfig(
            task_type=TaskType.CAUSAL_LM,
            hidden_size=hidden_size,
            adapters=adapters,
            # gating 相关
            enable_softmax=(top_k_lora is None),
            enable_softmax_topk=(top_k_lora is not None),
            top_k_lora=top_k_lora,
            softmax_temperature=softmax_temperature,
            layerwise_scalings=layerwise_scalings,
            # gating MLP 结构
            xlora_depth=xlora_depth,
            # xlora_size / xlora_dropout_p 用默认即可
            use_trainable_adapters=use_trainable_adapters,
            global_scaling_weight=global_scaling_weight,
        )

        llm_for_fine_tuning = get_peft_model(llm, xlora_cfg)

        if use_quantization:  # 开启 gradient checkpointing 和量化无关，即使没量化也可以开，用来省显存；只是会稍微牺牲一点算力（多做前向）
            llm_for_fine_tuning.gradient_checkpointing_enable()

        trainable_params = [p for p in llm_for_fine_tuning.parameters() if p.requires_grad]
        total_trainable = sum(p.numel() for p in trainable_params)
        print(f"[XLORA] Trainable parameters: {total_trainable}")
        return llm_for_fine_tuning


    @staticmethod
    def supervised_fine_tuning(llm: PreTrainedModel, dataset: Union[DTDataset, ExamplesDataset, PostThinkDataset],
                               output_dir: str = "ds-dt-xlora",
                               learning_rate: float = 5e-5, logging_steps: int = 1,
                               per_device_train_batch_size: int = 1, num_train_epochs: int = 3,
                               prompt_logging: bool = False, prompts: Optional[List[str]] = None,
                               answers: Optional[List[str]] = None,
                               max_generation_tokens: int = 32,
                               running_average_window: int = 100, prompt_logging_frequency: int = 1,
                               temperature: float = 0.7, save_steps: int = 100, save_limit: int = 2,
                               gradient_accumulation_steps: int = 1, progress_save_frequency: int = 1,
                               seed: int = 91501) -> None:
        if prompts is None:
            prompts = []
        if answers is None:
            answers = []
        gen_kwargs = dict(max_new_tokens=max_generation_tokens, temperature=temperature, do_sample=True)
        args = TrainingArguments(
            output_dir=output_dir, bf16=True,
            per_device_train_batch_size=per_device_train_batch_size, num_train_epochs=num_train_epochs,
            learning_rate=learning_rate, logging_steps=logging_steps,
            save_strategy=constants.LORA.SAVE_STRATEGY_STEPS, save_steps=save_steps,
            save_total_limit=save_limit, gradient_accumulation_steps=gradient_accumulation_steps, seed=seed)
        
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
        trainer.train()
        trainer.save_model(output_dir=output_dir)