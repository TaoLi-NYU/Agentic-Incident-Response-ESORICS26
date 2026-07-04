"""
samples: List[str] 到底是什么？
这里的 samples 不是 “instruction / answer” 对，而是：
每一个元素 = 一整个“恢复轨迹 episode”的文本表示。
这个文本是谁构造的？
→ 就是 synthetic_dataset_generator.py 里那段：

seq.append(
    "<obs>" + state_t +
    "<action>" + action_t +
    "<cost>" + cost_to_go_t
)
...
seq.append("</history>")
return " ".join(seq)

也就是说，一条 sample 可能长这样（简化版）：

<history>
<obs>[0:0] IDS alert X0
<action>block IP 1.2.3.4
<cost> 15
<obs>[0:1] IDS alert X1
<action>reset password
<cost> 14
...
</history>

这才是 Decision Transformer 的“精髓”：
把 (状态, 动作, cost-to-go) 序列编码进一条文本里；
每条样本是一整个 episode。
DTDataset 做的事情就是：
把这些长字符串送进 tokenizer，变成 input_ids + attention_mask
"""


from typing import List, Dict, Any, Union
from torch.utils.data import Dataset
from transformers import PreTrainedTokenizer
import llm_recovery.constants.constants as constants
import torch


class DTDataset(Dataset[Dict[str, torch.Tensor]]):
    """
    A torch dataset of synthetic data
    """

    def __init__(self, samples: List["str"], tokenizer: PreTrainedTokenizer):
        """
        Initializes the dataset with a given list of samples.

        :param samples: the list of data samples
        :param tokenizer: the LLM tokenizer
        """
        self.samples = samples
        self.tokenizer = tokenizer

    def __len__(self):
        """
        :return: The length of the dataset
        """
        return len(self.samples)

    def __getitem__(self, i):
        """
        Retrieves the ith data sample in tokenized form

        :param i: the index of the data sample
        :return: a dictionary with input ids (the token ids and an attention mask)
        """
        
        """
        self.tokenizer(sample, return_tensors="pt")

        return_tensors="pt"：让 tokenizer 直接返回 PyTorch tensor, 而不是普通的 list
        返回值类似：
        {
        "input_ids": tensor([[...]]),       # shape: [1, seq_len]
        "attention_mask": tensor([[...]]),  # shape: [1, seq_len]
        }

        constants.GENERAL.INPUT_IDS: tokenized_input_sample.input_ids[0]
        因为 tokenizer 默认会给你加一个 batch 维度，所以是 [1, seq_len]
        [0] 之后就变成 [seq_len] 一维向量，方便后面 pad_sequence 操作
        attention_mask[0] 同理
        """
        sample = self.samples[i]
        tokenized_input_sample = self.tokenizer(sample, return_tensors=constants.GENERAL.PYTORCH)
        return {constants.GENERAL.INPUT_IDS: tokenized_input_sample.input_ids[0],
                constants.GENERAL.ATTENTION_MASK: tokenized_input_sample.attention_mask[0]}


    def collate(self, batch: List[Any]) -> Dict[str, Union[List[Any], torch.Tensor]]:
        """
        Takes a batch of tokenized samples, pads them so they have the same length, and  returns a dictionary of
        input_ids (tokenized ids), attention_mask (tokenized mask), and labels, which can be used for supervised
        fine-tuning.

        :param batch: the batch of tokenized samples
        :return: the dictionary with input ids, attention mask, and labels.
        """

        """
        batch = [
        {"input_ids": Tensor(len_1), "attention_mask": Tensor(len_1)},
        {"input_ids": Tensor(len_2), "attention_mask": Tensor(len_2)},
        ...
        ]

        """
        ids = [b[constants.GENERAL.INPUT_IDS] for b in batch]
        mask = [b[constants.GENERAL.ATTENTION_MASK] for b in batch]
        """
        ids 是一个 list, 里面元素都是 1D tensor(长度各不相同)
        ids[0]: [seq_len_0]
        ids[1]: [seq_len_1]
        ...
        mask 同理
        """

        ids_tensor = torch.nn.utils.rnn.pad_sequence(ids, batch_first=True,
                                                     padding_value=self.tokenizer.pad_token_id)
        mask_tensor = torch.nn.utils.rnn.pad_sequence(mask, batch_first=True, padding_value=0)
        """
        batch_first=True:
        输出 shape 是 [batch_size, max_len]
        如果是 False, 则 [max_len, batch_size]
        """
        labels = ids_tensor.clone()
        return {constants.GENERAL.INPUT_IDS: ids_tensor, constants.GENERAL.ATTENTION_MASK: mask_tensor,
                constants.GENERAL.LABELS: labels}
