from typing import List, Dict
from torch.utils.data import Dataset
from transformers import PreTrainedTokenizer
import torch
import llm_recovery.constants.constants as constants

"""
identifiers 标识符
input_ids = input token identifiers 

1.token vocabulary (vocab)

<pad> → id = 0
"Incident" → 10
"detected" → 11
"on" → 12
"server" → 13
"." → 14
"Isolate" → 20
"the" → 21
"and" → 22
"collect" → 23
"logs" → 24

2.假设有一条训练样本：

instruction(prompt):  "Incident detected on server."
answer(模型要学会生成的响应):  "Isolate the server and collect logs."

对于 Hugging Face 的 tokenizer,正常调用后返回的是一个“字典”,典型长这样:
prompt_tokens = {
    "input_ids": [...],
    "attention_mask": [...]
    # 有时还会有 token_type_ids 等字段，但这里没有用
}

prompt_tokens["input_ids"] = [10, 11, 12, 13, 14]
# 对应:Incident, detected, on, server, "."
answer_tokens["input_ids"] = [20, 21, 13, 22, 23, 24, 14]
# 对应:Isolate, the, server, and, collect, logs, "."

prompt_tokens["attention_mask"] = [1, 1, 1, 1, 1]
answer_tokens["attention_mask"] = [1, 1, 1, 1, 1, 1, 1]


3.ExamplesDataset 里的 __getitem__ 怎么拼？
3.1 拼接 input_ids 和 attention_mask

input_ids = prompt_ids + answer_ids
attention_mask = prompt_mask + answer_mask
代入上面的数：
input_ids = [10, 11, 12, 13, 14, 20, 21, 13, 22, 23, 24, 14]
attention_mask = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
这就相当于一个完整输入：
「Incident detected on server. Isolate the server and collect logs.」
让模型看到完整上下文

3.2 构造 labels(关键！)
labels = [-100] * len(prompt_tokens["input_ids"]) + answer_tokens["input_ids"]
也就是：
prompt 部分长度 = 5 → [ -100, -100, -100, -100, -100 ]
answer 部分直接用真实 id → [ 20, 21, 13, 22, 23, 24, 14 ]

labels = [
    -100, -100, -100, -100, -100,    # 对应 prompt: Incident detected on server .
    20, 21, 13, 22, 23, 24, 14       # 对应 answer: Isolate the server and collect logs .
]


4. collate 的例子：两个样本 + padding

再加一条比较短的样本，方便看 padding:
第二条样本：
instruction2:"Incident detected."  →  token id: [10, 11, 14]
answer2:"Isolate the server." → [20, 21, 13, 14]

4.1 第二条样本经过 __getitem__:
input_ids_2 = [10, 11, 14, 20, 21, 13, 14]
attention_mask_2 = [1, 1, 1, 1, 1, 1, 1]
labels_2 = [
    -100, -100, -100,    # prompt: Incident detected .
    20, 21, 13, 14       # answer: Isolate the server .
]

4.2 现在 batch 里有两条样本

batch = [
    { "input_ids": tensor(input_ids_1), "attention_mask": ..., "labels": ... },
    { "input_ids": tensor(input_ids_2), "attention_mask": ..., "labels": ... },
]

第一条 seq_len_1 = 12
第二条 seq_len_2 = 7
collate 要把它们 pad 到同一个长度 = 12


4.3 collate 里的 padding 结果
4.3.1 input_ids_tensor(用 pad_token_id = 0 填充)
input_ids_tensor =
[
  [10, 11, 12, 13, 14, 20, 21, 13, 22, 23, 24, 14],  # 样本 1, 长度 12
  [10, 11, 14, 20, 21, 13, 14, 0,  0,  0,  0,  0 ],  # 样本 2, 长度 7→pad到12
]
# 形状: [batch_size=2, max_seq_len=12]

4.3.2 attention_mask_tensor(pad 位置用 0)
attention_mask_tensor =
[
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],  # 样本 1, 全是有效 token
  [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],  # 样本 2, 后面 5 个是 padding
]
# 形状: [2, 12]

4.3.3 labels_tensor(pad 部分也用 -100)
labels_tensor =
[
  [-100, -100, -100, -100, -100, 20, 21, 13, 22, 23, 24, 14],
  [-100, -100, -100, 20,   21,   13, 14, -100, -100, -100, -100, -100],
]
# 形状: [2, 12]

注意：
对 样本 2, 原来的 labels 长度是 7, 后面 5 个 pad 位置都填成 -100
所以 Loss 计算时：
prompt 部分(前几位 -100)被忽略
pad 部分(后几位 -100)也被忽略
只在 answer 有真实 id 的位置上计算损失


5. 用一句话再总结一下逻辑

对每条 (instruction, answer)
tokenizer 后：
prompt: 一串 id
answer: 一串 id
input_ids = prompt + answer
labels = [-100]*len(prompt) + answer_ids
collate 时做 padding: 
input_ids: pad_token_id(比如 0)
attention_mask: pad 部分 0
labels: pad 部分也用 -100(同样忽略)

"""


class ExamplesDataset(Dataset[Dict[str, torch.Tensor]]):
    """
    A torch dataset of prompt-answer examples
    继承 Dataset, 并注明这个 Dataset 的「单个样本」类型是 Dict[str, torch.Tensor]
    比如 {"input_ids": tensor(...), "attention_mask": tensor(...), "labels": tensor(...)}
    它在类型系统里的含义是：
    这个数据集的 __getitem__(idx) 会返回一个 Dict[str, torch.Tensor]

    class ExamplesDataset(Dataset):   # 二者运行结果上一致
    """

    def __init__(self, instructions: List["str"], answers: List["str"], tokenizer: PreTrainedTokenizer):
        """
        PreTrainedTokenizer 是类型注释type hint
        默认值的写法是: tokenizer: PreTrainedTokenizer = None 或 = some_tokenizer
        Initializes the dataset with given lists of instructions and answers

        :param instructions: the list of instructions
        :param answers: the list of answers
        :param tokenizer: the LLM tokenizer
        """
        self.instructions = instructions
        """
        instructions = dataset["train"]["instructions"][0]
        answers = dataset["train"]["answers"][0]
        
        dataset["train"]["instructions"]   # 形如 [ ["instr0", "instr1", ...] ]
        dataset["train"]["instructions"][0]  # → ["instr0", "instr1", ...]
        """

        self.answers = answers
        self.tokenizer = tokenizer

    def __len__(self):
        """
        :return: The length of the dataset
        """
        return len(self.instructions)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        prompt = self.instructions[idx]
        answer = self.answers[idx]
        """
        prompt = "Describe the incident based on these logs: ..."
        answer = "Step 1: Isolate the affected host...\nStep 2: ... "
        """

        # prompt_tokens = self.tokenizer(prompt, add_special_tokens=False)
        # answer_tokens = self.tokenizer(answer, add_special_tokens=False)   内存OOM，这里加了截断和最大长度限制

        
        MAX_LENGTH = 256  
        prompt_tokens = self.tokenizer(
        prompt,
        add_special_tokens=False,
        truncation=True,
        max_length=MAX_LENGTH,
    )
        answer_tokens = self.tokenizer(
            answer,
            add_special_tokens=False,
            truncation=True,
            max_length=MAX_LENGTH,
        )


        """
        self.tokenizer(...) 返回的是一个 字典，通常长这样：
        {
            "input_ids": [p1, p2, p3, ...],
            "attention_mask": [1, 1, 1, ...]    
        }
        add_special_tokens=False
        不自动在前后加 <bos>, <eos>, [CLS]  (classification token), [SEP] 这种；
        说明作者想手动拼接 prompt + answer, 自己控制结构
        """


        input_ids = prompt_tokens[constants.GENERAL.INPUT_IDS] + answer_tokens[constants.GENERAL.INPUT_IDS]
        attention_mask = (prompt_tokens[constants.GENERAL.ATTENTION_MASK] +
                          answer_tokens[constants.GENERAL.ATTENTION_MASK])
        # Label: -100 for prompt tokens (ignored), actual ids for answer tokens
        """
        constants.GENERAL中常量带入
        
        class GENERAL:
        INPUT_IDS = "input_ids"
        ATTENTION_MASK = "attention_mask"
        PYTORCH = "pt"
        LABELS = "labels"
        LEARNING_RATE = "learning_rate"
        GRAD_NORM = "grad_norm"
        LOSS = "loss"
        MODEL = "model"
        MAX_NEW_TOKENS = "max_new_tokens"
        N_A = "n/a"

        input_ids = prompt_tokens["input_ids"] + answer_tokens["input_ids"]
        attention_mask = prompt_tokens["attention_mask"] + answer_tokens["attention_mask"]
        labels = [-100] * len(prompt_tokens["input_ids"]) + answer_tokens["input_ids"]

        """

        labels = [-100] * len(prompt_tokens[constants.GENERAL.INPUT_IDS]) + answer_tokens[constants.GENERAL.INPUT_IDS]
        return {
            constants.GENERAL.INPUT_IDS: torch.tensor(input_ids, dtype=torch.long),
            constants.GENERAL.ATTENTION_MASK: torch.tensor(attention_mask, dtype=torch.long),
            constants.GENERAL.LABELS: torch.tensor(labels, dtype=torch.long),
        }
        


    def collate(self, batch: List[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
        """
        batch = [
            { "input_ids": tensor(input_ids_1), "attention_mask": ..., "labels": ... },
            { "input_ids": tensor(input_ids_2), "attention_mask": ..., "labels": ... },
        ]
        
        batch: List[Dict[str, torch.Tensor]]    冒号 : 后面是  “参数类型注解”(type hint)
        
        -> Dict[str, torch.Tensor]   这个箭头 -> 是“返回值类型注解”
        含义：这个函数会返回一个字典，键是字符串，值是 torch.Tensor

        def collate(self, batch: List[Dict[str, torch.Tensor]]-> Dict[str, torch.Tensor]):
        会报错 syntax error
        Python 语法规定：返回值类型注解 -> ... 必须写在整个参数列表的右括号 ) 之后

        """

        """
        Takes a batch of tokenized samples, pads them so they have the same length, and  returns a dictionary of
        input_ids (tokenized ids), attention_mask (tokenized mask), and labels, which can be used for supervised
        fine-tuning.

        :param batch: the batch to process
        :return: the processed batch
        """
        input_ids = [b[constants.GENERAL.INPUT_IDS] for b in batch]
        attention_mask = [b[constants.GENERAL.ATTENTION_MASK] for b in batch]
        labels = [b[constants.GENERAL.LABELS] for b in batch]
        input_ids_tensor = torch.nn.utils.rnn.pad_sequence(input_ids, batch_first=True,
                                                           padding_value=self.tokenizer.pad_token_id)
        """
        tokenizer 里一般会有一个特殊的 pad token(补齐用的符号),比如 <pad>
        为什么不能直接写 padding_value=0 当作 pad_token_id？
        关键点: “0” 不一定是 pad 的 id。
        不同模型的 vocab 设计不一样，比如：
        有的模型：
        pad_token_id = 0
        eos_token_id = 2
        有的模型：
        pad_token_id = 2
        eos_token_id = 2 (常见：没有专门 pad, 就拿 eos 当 pad)
        还有的模型默认根本没有 pad_token, tokenizer.pad_token 是 None, pad_token_id 也是 None

        batch_first=True: 输出 [batch, seq]  否则默认输出 [seq, batch]

        1. torch
        PyTorch 顶层包。
        里面有：张量 torch.Tensor、数学函数、随机数、cuda 等等。
        
        2. torch.nn
        nn = neural networks, 存各种神经网络模块：
        nn.Linear, nn.Conv2d, nn.LSTM, nn.Transformer…
        还有一些子包，比如 nn.functional、nn.utils。

        3. torch.nn.utils
        utils 就是 utilities (工具集合) 的缩写。
        放的是一些“辅助功能”，比如：
        梯度裁剪 nn.utils.clip_grad_norm_
        参数打包/拆包工具
        RNN/LSTM 相关工具等。

        4. torch.nn.utils.rnn
        这里又是一个子模块，专门放“跟序列/RNN 相关的小工具”：
        pad_sequence
        pack_padded_sequence
        pad_packed_sequence
        这些都是为了解决“每个样本长度不一样”的问题
        """

        attention_mask_tensor = torch.nn.utils.rnn.pad_sequence(attention_mask, batch_first=True, padding_value=0)
        labels_tensor = torch.nn.utils.rnn.pad_sequence(labels, batch_first=True, padding_value=-100)
        return {
            constants.GENERAL.INPUT_IDS: input_ids_tensor,
            constants.GENERAL.ATTENTION_MASK: attention_mask_tensor,
            constants.GENERAL.LABELS: labels_tensor
        }
