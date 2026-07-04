import random
from datasets import load_dataset
# 来自 HuggingFace datasets 库，用来加载作者整理好的事件响应数据集
from transformers import AutoModelForCausalLM, AutoTokenizer, TextIteratorStreamer
# AutoModelForCausalLM: transformers 里“自动选择合适架构的因果语言模型”类，用来加载一个已经 fine-tune 好的 LLMIncidentResponse 模型
# AutoTokenizer 对应的分词器
# TextIteratorStreamer: transformers 的一个流式输出工具，可以一边生成一边往外吐 token，类似 ChatGPT 那样一串一串打印
import threading
#Python 线程库，这里用一个子线程去跑 model.generate，主线程负责读 streamer 的输出并打印

if __name__ == '__main__':

#这是 Python 常见习惯：
#表示「只有当这个脚本被直接运行时才执行下面的代码」。
#如果将来有人 import load_model，下面这坨就不会自动跑，避免导入时就开始生成

    model = AutoModelForCausalLM.from_pretrained("kimhammar/LLMIncidentResponse")
    # from_pretrained 只是一个历史遗留的 API 名字,从某个已有的 checkpoint 仓库里，把权重加载出来。这个 checkpoint 可以是：  
    # 基础/底座模型（foundation model）
    # 例如：meta-llama/Llama-3-8B-Instruct
    # 也可以是别人 在底座模型上继续 fine-tune 之后的模型
    # 例如你自己训练好的情感分析模型、领域模型等等
    tokenizer = AutoTokenizer.from_pretrained("kimhammar/LLMIncidentResponse")
    #加载与这个模型配套的分词器（vocab、特殊 token 设置等）
    dataset = load_dataset("kimhammar/CSLE-IncidentResponse-V1", data_files="examples_16_june.json")
    # 论文里那 68,000 条那个数据集 (500个testbed生成，67500 frontier LLM生成)

    instructions = dataset["train"]["instructions"][0]
    answers = dataset["train"]["answers"][0]
    model.eval()
    """
    把模型切到评估模式(evaluation mode): 关掉 dropout 等训练相关的行为；
    不会启用梯度计算（虽然后面没有显式 torch.no_grad()，但是没有 loss/backward, 也不会训练)
    """
    instruction = random.choice(instructions)
    """
    从 instructions 这一串指令中随机选一条；
    模拟「从数据集中随机抽一条事件描述，让 LLM 输出响应方案
    """
    inputs = tokenizer(instruction, return_tensors="pt").to(model.device)
    """
    把自然语言字符串 instruction 编码成 token id:
    return_tensors="pt"：直接返回 PyTorch 张量(input_ids, attention_mask 等)
    {
    "input_ids": tensor([[...]]).to(device),
    "attention_mask": tensor([[...]]).to(device)
    }

    1.句子长短不一，需要 padding 对齐
    一个 batch 里，有的 prompt 10 个 token, 有的 100 个。
    为了凑成一个张量，要把短的右边添 0(padding)
    但模型不能真的去“注意”这些 pad 0, 否则会把垃圾信息也当内容。
    所以：
    attention_mask = 1 的位置：可以参与注意力计算
    attention_mask = 0 的位置：在 self-attention 里被屏蔽掉(softmax 前加 -inf)

    2.有的模型有更复杂的掩码逻辑
    对于 Causal LM,本身还有一个「只能看前面，不能看未来 token」的因果 mask(decoder 自己内部构建)
    HF 会在内部把 因果 mask * attention_mask 组合起来一起用，所以我们只要把 padding 哪些位置标出来就行
    """
    gen_kwargs = dict(max_new_tokens=6000, temperature=0.8, do_sample=True)
    """
    gen_kwargs 是一堆传给 model.generate 的参数
    max_new_tokens=6000: 最多生成 6000个新token
    temperature=0.8: 温度稍稍加大一点，让输出多样性更强；
    do_sample=True: 启用采样(而不是贪心/beam search)
    """
    streamer = TextIteratorStreamer(tokenizer, skip_special_tokens=True, skip_prompt=True)
    """
    负责把 generate 的输出流式地解码成文本；
    skip_special_tokens=True:忽略 <pad>、</s> 等特殊 token:
    skip_prompt=True:不把输入的 prompt 重复打印一遍，只输出新生成部分
    """
    thread = threading.Thread(target=model.generate, kwargs={**inputs, **gen_kwargs, "streamer": streamer})
    """
    这里没有直接 model.generate(**inputs, **gen_kwargs, streamer=streamer)，而是：
    创建一个 Thread,让它在后台执行 model.generate(...)
    同时主线程可以一边从 streamer 里读 token,一边打印
    
    kwargs={**inputs, **gen_kwargs, "streamer": streamer}
    把 inputs 这个 dict(包含 input_ids, attention_mask 等）和 gen_kwargs 合并；
    再加上 "streamer": streamer
    
    最终等价于：
    model.generate(
    input_ids=...,
    attention_mask=...,
    max_new_tokens=6000,
    temperature=0.8,
    do_sample=True,
    streamer=streamer
    )
    """
    thread.start()
    for new_text in streamer:
        print(new_text, end="", flush=True)

    """
    TextIteratorStreamer 本身就是一个迭代器：
    每当 generate 生成一部分新 token,它就会 yield 一小段对应的文本；
    for new_text in streamer:
    主线程不断从 streamer 里拿出一小段字符串；
    print(new_text, end="", flush=True)
    end=""：避免每次换行，像连续输出一样；
    flush=True: 立即把缓冲区刷到终端上,实现「一串一串往外滚」的效果。
    这就实现了一个最简版的「流式事件响应 LLM」demo:
    从数据集中随机选一条 incident 描述 → 用作者的模型生成响应计划 → 实时打印在屏幕上
    """
