from typing import Dict, Union, Tuple
from transformers import (AutoTokenizer, AutoModelForCausalLM, PreTrainedTokenizer, PreTrainedModel,
                          BitsAndBytesConfig, AutoConfig)
import torch
import llm_recovery.constants.constants as constants

"""
PreTrainedTokenizer:抽象“父类”。定义分词器应该长什么样，有哪些接口、基本逻辑.
AutoTokenizer:一个“入口/工厂”，根据 checkpoint 自动实例化一个具体的 PreTrainedTokenizer 子类
"""
class LoadLLM:
    """
    Class with utility functions to load LLM models.
    """


    """
    1.实例方法(最常见)
    class A:
        def func(self, x):
            ...
    第一个参数是 self, 代表“这个类的实例”。
    调用时要先创建对象：
    a = A()
    a.func(10)
    
    2.类方法(@classmethod) —— 先不用管

    3.静态方法(@staticmethod) —— 就是“普通函数”
    class A:
        @staticmethod
        def func(x):
            ...
    没有 self 参数，就像一个“普通函数，只不过放在类的命名空间里”。
    调用方式可以是：
    A.func(10)          # 直接用类名调用
    a = A()
    a.func(10)          # 也可以通过实例，但不会用到 a
    """
    @staticmethod
    def load_llm(llm_name: str, device_map: Union[Dict[str, int], str] = constants.GPU.AUTO,
                 num_gpus: int = 1, use_quantization: bool = True) \
            -> Tuple[PreTrainedTokenizer, PreTrainedModel]:
        """
        # Load llm默认True,为了训练Xlora, 改成了False
        Utility function for loading a pretrained LLM from huggingface.

        :param llm_name: the name of the pretrained LLM.
        :param device_map: the device map for loading the LLM, i.e., which GPUs to load it on.
        Union[...] 的意思是：可以是 A 类型,也可以是 B 类型,要么是 Dict[str, int]：例如 {"": 0} 或者 {"model.layers.0": 0, "model.layers.1": 1, ...}; 要么是 str:例如 "auto"、"distributed"
        默认值是 constants.GPU.AUTO, 也就是 "auto"
        :param use_quantization: boolean flag indicating whether to use quantization.
        :return: The tokenizer and the LLM
        """

        """
        byte 字节     bit 比特
        字节和比特: 1 个 byte = 8 个 bit
        bit: 0 或 1  
        byte: 一串 8 个 0/1, 例如:01001010
        1 B = 1 Byte = 1 
        1 KB ≈ 1024 B
        1 MB ≈ 1024 KB
        1 GB ≈ 1024 MB
        1 TB ≈ 1024 GB

        如果一个模型有 14B 参数(fp16): 大约 14e9 * 2 bytes ≈ 28 GB 显存
        """
        tokenizer = AutoTokenizer.from_pretrained(llm_name, use_fast=True)
        # True：优先使用 Fast Tokenizer（用 Rust 实现的版本，来自 tokenizers 库） 推理和训练都能更快一点
        tokenizer.pad_token = tokenizer.eos_token
        """
        这行非常关键，和你前面 ExamplesDataset.collate 里的这一句是配套的：
        input_ids_tensor = pad_sequence(
            input_ids,
            batch_first=True,
            padding_value=self.tokenizer.pad_token_id
        )
        
        id -> token
        0  -> <pad>      # pad_token
        1  -> <bos>      # begin of sequence
        2  -> </s>       # eos_token (end of sequence)
        
        很多 Causal LM(因果语言模型,用过去的token预测下一个token)(比如 LLaMA、Qwen 等)原本是“只做生成”的，
        它们的 tokenizer 有：
        eos_token(end of sequence)
        但 可能没有定义 pad_token, pad_token 和 pad_token_id 可能是 None。
        如果你直接用：
        self.tokenizer.pad_token_id
        而 tokenizer 没定义 pad token, 就会报错 / 是 None。
        所以项目作者做了一个常见 trick:
        把 pad_token 设置成 eos_token
        tokenizer.pad_token = tokenizer.eos_token
        这会自动同时把 pad_token_id 设置成 eos_token_id
        """
        if device_map == constants.GPU.DISTRIBUTED:  # device_map 默认是 "auto"
            device_map = LoadLLM.create_device_map(num_gpus=num_gpus, llm_name=llm_name)
        if use_quantization:  # use_quantization 默认是 True
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True, # 用 4bit 的方式加载权重”.没有它（或者是 False），就是正常：fp16 / bf16 / fp32 权重
                bnb_4bit_use_double_quant=True,  # 是否使用 double quantization（二次量化）具体实现细节是 bitsandbytes 内部的优化，你不需要记死是 int8 还是 fp8，只要知道“大方向是再压一遍”就够了
                bnb_4bit_quant_type=constants.GPU.NF4, # 量化类型: nf4 / fp4 / int4,权重本体的 4bit 表示方式nf4
                bnb_4bit_compute_dtype=torch.bfloat16, # 反量化
            )
            # bnb 是 bitsandbytes 的缩写. bitsandbytes = 一个专门做 8bit/4bit 量化 的库

            """
            把一堆 float 权重分成一块一块的 group(比如每 64 个一组)
            对每一组找一个 scale(尺度因子)，然后用 int4/NF4 表示相对值
            权重 ≈ scale * 量化后的值
            这样，除了存 int4 权重本身，还要存 scale(浮点数)
            double quantization 的想法是：
            “既然 scale 自己也是浮点数，是不是也可以再做一遍量化？”
            → 就是把「存权重」这个过程压两层

            通常 不会 把一堆 float 权重按从小到大排序再分组
            而是直接按「原始顺序 / 按通道」分成一组组
            排序会破坏权重在网络结构中的对应关系

            w = [ 0.10, -0.30, 0.25, 1.20,   -0.50, 0.80, -2.00, 0.40 ]
            按原始顺序分组 (group_size=4):
            group 1: [ 0.10, -0.30, 0.25, 1.20 ]  → scale1
            group 2: [ -0.50, 0.80, -2.00, 0.40 ] → scale2  (最终把一堆scale压缩)
            max_abs = max(|0.10|, |-0.30|, |0.25|, |1.20|) = 1.20
            假设用 有符号 int4,整数范围是:
            q ∈ [-7, 7]   (一共 15 个值，加上 0)  用15个离散值表示实数 
            我们希望：实数 w ≈ scale * q
            更具体一点，构造：
            scale = max_abs / 7   ,   scale = 1.20 / 7 ≈ 0.1714
            q₀ = round(0.10 / 0.1714) ≈ round(0.583) = 1
            反量化： ŵ₀ = scale * q₀ ≈ 0.1714 * 1 ≈ 0.1714
            (和原来的 0.10 不完全一样，有误差)
            q₁ = round(-0.30 / 0.1714) ≈ round(-1.75) = -2
            q₂ = round(0.25 / 0.1714) ≈ round(1.46) = 1
            q₃ = round(1.20 / 0.1714) ≈ round(7.00) = 7
            """

            """
            普通 int4 量化：
            直接把权重缩放到一个区间，然后线性映射到 16 个离散值(0~15)
            假设权重是 [-a, a]，那就每个小格宽度一样；
            对「正态分布」那种中间密、两侧稀的权重不是最友好
            
            NF4(NormalFloat4)
            利用权重大致服从「高斯 / 正态分布」这个事实；
            把 16 个离散值分布在更符合正态分布的点上（不是均匀分布）；
            等价于：“在权重密集的区域（接近 0 一带）多分配点，在极端大的区域少分配点”，
            让精度集中在模型最敏感的区域
            
            quant_type="nf4" 是目前实践中「效果最好」的 4bit 方案之一；
            对 LLM 权重来说，比简单 int4 / fp4 更适合

            存储精度 ≠ 计算精度
            compute_dtype = torch.bfloat16:
            指定解码后用 bfloat16 做计算；
            bfloat16 有跟 fp32 差不多的 指数范围，但 mantissa 少一些，适合深度学习；
            现在主流大模型训练/推理也广泛用 bf16 (尤其是 A100/H100 上)
            """

            llm = AutoModelForCausalLM.from_pretrained(llm_name, device_map=device_map,
                                                       quantization_config=quantization_config,
                                                       attn_implementation=constants.GPU.SDPA, # sdpa = scaled dot-product attention(缩放点积注意力，Transformer 标准注意力机制)
                                                       torch_dtype=torch.bfloat16) # 推理/训练计算时用 bfloat16 算, 和 bnb_4bit_compute_dtype=torch.bfloat16一致
            llm.use_memory_efficient_attention = True  # 启用内存高效注意力机制，节省显存
        else:
            llm = AutoModelForCausalLM.from_pretrained(llm_name, device_map=device_map, torch_dtype=torch.float16)
        return tokenizer, llm

    @staticmethod
    def create_device_map(num_gpus: int, llm_name: str) -> Dict[str, int]:
        """
        Utiltiy function for automatically creating a device map for distributed training.

        :param num_gpus: the number of GPUs
        :param llm_name: the name of the LLM
        :return: the device map
        """
        config = AutoConfig.from_pretrained(llm_name, trust_remote_code=True)
        num_layers = config.num_hidden_layers
        """
        AutoConfig.from_pretrained(llm_name, trust_remote_code=True)
        从 HF Hub / 本地 拉这个模型的配置对象
        trust_remote_code=True: 允许模型仓库里有自定义代码(有些 LLAMA/Qwen 需要)
        config.num_hidden_layers:
        就是这个 LLM 里有多少个 Transformer block
        比如 14B 模型可能有 40 层、60 层之类
        """
        base = num_layers // num_gpus
        remainder = num_layers % num_gpus

        """
        num_layers = 10, num_gpus = 3
        base = 10 // 3 = 3
        remainder = 10 % 3 = 1
        """

        layers_each = [base] * num_gpus  # [3, 3, 3]
        for i in range(remainder): # 0 到 remainder-1
            layers_each[i] += 1

        if layers_each[0] > 0:
            layers_each[0] -= 1
            tgt_gpu = layers_each.index(min(layers_each))
            layers_each[tgt_gpu] += 1

        """
        注意: embedding / norm / lm_head 都被固定在 GPU0 上了 (下面会看到)
        所以如果再把很多层都放在 GPU0, 0 号卡会很吃紧
        1.如果第 0 块 GPU 原来分到的层数 > 0
        2.找一块当前层数最少的 GPU
        3.把刚刚那一层加到这块 GPU 上

        index:
        nums = [10, 20, 30, 20]
        print(nums.index(10))  # 0   因为 10 在位置 0  10在列表中首次出现时候的下标
        """
        # sanity check, 确保分配的层数加起来等于总层数
        assert sum(layers_each) == num_layers

        device_map = {constants.GPU.MODEL_EMBED_TOKENS: 0, constants.GPU.MODEL_NORM: 0,
                      constants.GPU.LM_HEAD: 0}
        """
        model.embed_tokens: 输入 embedding 层 → 放在 GPU0
        model.norm: 最后一层的 LayerNorm(有的模型叫 model.norm) → 放在 GPU0
        lm_head: language modeling head(输出层) → 放在 GPU0

        embedding 和 lm_head 通常可以共享权重，放在同一个 GPU 比较自然；
        这些模块相对来说不是特别多层数，就固定统一放在 0 上
        """

        """
        第 1 次循环： for gpu,n in enumerate(layers_each):
        gpu = 0 (index)
        n = 10 (layers_each[0])
        
        当 gpu=0, n=6 时(比如两块卡:layers_each = [6, 6],num_layers = 12):
        layer_idx = 0~5
        device_map["model.layers.0"] = 0
        ...
        device_map["model.layers.5"] = 0
        """
        layer_idx = 0
        for gpu, n in enumerate(layers_each):
        # enumerate: 在你遍历一个可迭代对象（list、tuple、字符串等）时，同时拿到“下标”和“元素值”
            for _ in range(n):
                device_map[f"{constants.GPU.MODEL_LAYERS}.{layer_idx}"] = gpu
                layer_idx += 1
        return device_map
        """
        device_map 形如：
                {
            "model.embed_tokens": 0,
            "model.norm": 0,
            "lm_head": 0,
            "model.layers.0": 0,
            "model.layers.1": 0,
            "model.layers.2": 0,
            "model.layers.3": 1,
            "model.layers.4": 1,
            "model.layers.5": 1,
            ...
        }
        """