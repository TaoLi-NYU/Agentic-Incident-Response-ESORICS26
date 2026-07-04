from typing import Dict, Any, Deque, List, Union
import random
import torch
from collections import deque
from transformers import (TrainerCallback, TrainerControl, TrainerState, TrainingArguments, PreTrainedModel,
                          PreTrainedTokenizer)
import llm_recovery.constants.constants as constants
from llm_recovery.decision_transformer.dt_dataset import DTDataset
from llm_recovery.fine_tuning.examples_dataset import ExamplesDataset
from llm_recovery.fine_tuning.post_think_dataset import PostThinkDataset
import time
import json


class LoggingCallback(TrainerCallback):
    """
    Callback for logging during LORA  training.
    """

    def __init__(self, prompts: List[str], answers: List[str], tokenizer: PreTrainedTokenizer,
                 dataset: Union[DTDataset, ExamplesDataset, PostThinkDataset],
                 window: int = 100, gen_kwargs: Dict[str, Any] | None = None, prompt_logging: bool = False,
                 prompt_logging_frequency: int = 1, progress_save_frequency: int = 1, seed: int = 29015) -> None:
        """
        Initializes the callback.

        :param prompts: List of prompts to use for testing during training
        :param answers: List of answers to use for testing during training
        :param tokenizer: the tokenizer for the LLM
        :param window: the length of the training window for computing running averages
        :param gen_kwargs: keyword arguments to use for test generation with the LLM
        :param dataset: dataset for training
        :param prompt_logging: Boolean flag indicating whether to log test-prompts during training
        :param prompt_logging_frequency: frequency of prompt logging
        :param progress_save_frequency: frequency of saving the training progress to disk
        :param seed: the random seed
        """
        self.prompts = prompts
        self.answers = answers
        self.tokenizer = tokenizer
        self.window = window
        self.dataset = dataset
        self.prompt_logging = prompt_logging
        self.losses: Deque[float] = deque(maxlen=window)
        self.gen_kwargs = gen_kwargs or {constants.GENERAL.MAX_NEW_TOKENS: 64}
        self.prompt_logging_frequency = prompt_logging_frequency
        self.avg_losses_logging: List[float] = []
        self.losses_logging: List[float] = []
        self.grad_norms: List[float] = []
        self.learning_rates: List[float] = []
        self.epochs: List[int] = []
        self.start_time: float = time.time()
        self.times_passed: List[float] = []
        self.steps: List[int] = []
        self.progress_save_frequency = progress_save_frequency
        self.seed = seed


    #告诉 PyTorch：这个函数里发生的所有 tensor 运算都不要构建计算图（不追踪梯度）
    @torch.no_grad()
    def _sample(self, llm: PreTrainedModel, prompt: str) -> str:
        """
        Utility function to sample from the LLM.

        :param llm: the LLM to sample from
        :param prompt: the prompt
        :return: the sampled output
        """
        
        model_was_training = llm.training  
        # 模型进入 _sample() 前的训练状态
        # Bool值，表示模型当前是否处于训练模式 True：训练模式，False：评估模式
        #因为这个 _sample() 会临时切换模型到 eval 做推理（下一行），推理完以后要恢复原状态
        llm.eval()  # 把模型切换到 评估模式
        inputs = self.tokenizer(prompt, return_tensors=constants.GENERAL.PYTORCH).to(llm.device)
        # 把字符串 prompt 变成模型能吃的 token ID，要返回 PyTorch tensor，并且把 tensor 放到和模型同一个设备上（GPU or CPU）
        # 当你 device_map="auto" 时，模型可能是多卡/多设备分布的；但你这里 .to(llm.device) 其实默认认为模型有一个主 device。大部分单卡训练没问题；多卡时更复杂，但你现在 colab 基本是一张卡，OK
        pad_id = self.tokenizer.pad_token_id or self.tokenizer.eos_token_id
        
        """这一行干啥？
        确定生成时要用哪个 token 当作 padding token
        tokenizer.pad_token_id: pad 的 token id(有的模型有，有的没有)
        tokenizer.eos_token_id: 句子结束 token id(几乎一定有)
        它用 Python 的 or:
        如果 pad_token_id 存在且不是 None/0 → 用 pad_token_id
        否则退而求其次，用 eos_token_id 作为 pad
        为什么要这么做？
        许多 causal LM (比如一些 LLaMA 系列) 默认没有 pad token
        但 .generate() 在 batch/padding 时可能需要 pad_token_id, 否则会警告甚至报错。
        所以作者用一个稳妥的 fallback: 没有 pad 就用 eos 当 pad"""

        output_ids = llm.generate(**inputs, pad_token_id=pad_id, **self.gen_kwargs) 
        """output_ids = llm.generate(
            input_ids=inputs["input_ids"],
            attention_mask=inputs["attention_mask"],
            ...
        )
        
        gen_kwargs:

        所以真正决定“是否随机/是否 deterministic”的是这里
        再把你设置的生成参数展开进去，比如：
        max_new_tokens
        do_sample
        temperature"""

        text = self.tokenizer.decode(output_ids[0], skip_special_tokens=True)
        """
        把 token ids 转回人类可读的字符串
        返回的 数据类型是 str (Python 字符串)
        (a) output_ids[0]
        因为 batch_size=1, 你只取第一条序列
        (b) decode(..., skip_special_tokens=True)
        将 token ids 拼成字符串
        skip_special_tokens=True 会删掉像 <pad>, <eos>, <bos> 等特殊 token
        """
        if model_was_training:
            llm.train()
        """
        如果进入 _sample() 前模型是训练模式(True)那推理完要切回训练模式
        """
        return str(text)

    # training.json 就是你这个 LoggingCallback.on_log() 里自己写出来的文件
    def on_log(self, args: TrainingArguments, state: TrainerState, control: TrainerControl, logs=None, **kwargs) \
            -> None:
        """
        This function is called by the trainer during the training phase

        :param args: training arguments
        :param state: state of the training process
        :param control: object that can be used for controlling the training (e.g., early stopping)
        :param logs: the logs stored during training
        :param kwargs: keyword arguments for the training
        :return:
        """

        """
        训练开始后, Trainer 内部会跑一个训练循环 (training loop). 在这个循环里，每隔 logging_steps (你在 TrainingArguments(logging_steps=...) 里设的), Trainer 就会：
        汇总这一段时间的训练信息 (loss、learning rate、grad norm 等)
        组装成一个字典 logs
        调用 callbacks: 
        callback_handler.on_log(args, state, control, logs=logs, ...)
        于是你的 LoggingCallback.on_log(..., logs=...) 就拿到了这个 logs
        
        所以 logs = Trainer 的“系统日志包裹”，不是你手写的变量
        
        logs = {
                "loss": 1.2345,
                "learning_rate": 9.5e-4,
                "grad_norm": 0.87,
                "epoch": 0.12
                }

        """
        try:
            loss = logs.get(constants.GENERAL.LOSS)
            self.losses.append(float(loss))
            rolling_loss = sum(self.losses) / len(self.losses)
            lr = logs.get(constants.GENERAL.LEARNING_RATE, constants.GENERAL.N_A)
            gn = logs.get(constants.GENERAL.GRAD_NORM, constants.GENERAL.N_A)
            if self.prompt_logging and state.global_step % self.prompt_logging_frequency == 0:  # logging_frequency是50
                model = kwargs[constants.GENERAL.MODEL]  # model
                prompt_idx = random.randint(0, len(self.prompts) - 1) # examples中 prompts=instructions 传入lora，lora 中prompts传入logging callback.py
                # 相当于从训练集抽样，拿到一个data point的instruction，然后生成answer
                prompt = self.prompts[prompt_idx]   
                answer = self.answers[prompt_idx]
                model_output = self._sample(model, prompt=prompt) # train -> eval -> train
                model_output = model_output[len(prompt):] # 这句是为了把前面重复的 prompt 切掉，只保留模型生成的“答案部分
                print(f"prediction:\n{model_output}\nlabel:\n{answer}\n", flush=True)  # prediction是模型输出，label是答案 
            
            minutes_passed = (time.time() - self.start_time) / 60
            progress = state.global_step / state.max_steps * 100
            print(f"Step: {state.global_step}, Epoch: {state.epoch:.4f}, Progress: {round(progress, 2)}%, "
                  f"Avg_loss={rolling_loss:.4f}, "
                  f"LR={lr:.8f}, Grad_norm={gn:.4f}, minutes: {minutes_passed:.4f}", flush=True)
            self.avg_losses_logging.append(rolling_loss)
            self.losses_logging.append(float(loss))
            self.grad_norms.append(gn)
            self.learning_rates.append(lr)
            self.times_passed.append(minutes_passed)
            self.steps.append(state.global_step)
            if state.global_step % self.progress_save_frequency == 0:
                with open("training.json", "w") as f:       # training.json 就是你这个 LoggingCallback.on_log() 里自己写出来的文件
                    training_state = {
                        "steps": self.steps,
                        "running_avg": self.window,
                        "seed": self.seed,
                        "avg_losses": self.avg_losses_logging,
                        "losses": self.losses_logging,
                        "grad_norms": self.grad_norms,
                        "learning_rates": self.learning_rates,
                        "times_passed": self.times_passed
                    }
                    json.dump(training_state, f)
        except Exception:
            pass
