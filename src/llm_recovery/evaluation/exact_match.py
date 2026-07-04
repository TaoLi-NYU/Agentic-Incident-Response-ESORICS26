from __future__ import annotations

import json
from typing import Iterable, List, Dict, Any, Optional


REQUIRED_FIELDS = [
    "is_attack_contained",
    "is_knowledge_sufficient",
    "are_forensics_preserved",
    "is_eradicated",
    "is_hardened",
    "is_recovered",
]

"""
    输入: 一段长文本 (prediction/label)
    输出：一个列表，每个元素是一段形如 {...} 的子串（括号匹配后的完整对象）
"""

"""
objects: 存所有提取出来的 {...} 子串
depth: 当前花括号嵌套层数
看到 { depth+1
看到 } depth-1
start_idx: 记录一个 JSON 对象开始 { 的位置
in_string: 当前是否在双引号字符串内部（JSON 的 "..."）
escape: 处理字符串里的 \"，避免误判字符串结束

JSON 里说的 “object” 指的是：
用 { ... } 包起来
里面是 "key": value 的键值对
key 必须是字符串（双引号）
value 可以是：字符串/数字/布尔/null/数组/对象

最终返回的objects 列表里，每个元素都是一个完整的 JSON 对象字符串 (包含 {})
"""

# _parse_state_json会用到
def _extract_json_objects(text: str) -> List[str]:
    objects: List[str] = []
    depth = 0
    start_idx = None
    in_string = False
    escape = False

    for i, ch in enumerate(text):
        if in_string:   # text 中""结束
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':  # text 中""开始
            in_string = True
            continue

        if ch == "{":
            if depth == 0:
                start_idx = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start_idx is not None:
                    objects.append(text[start_idx : i + 1])  # 再list中添加一个完整的JSON对象
                    start_idx = None
    return objects


"""
给_parse_state_json调用

输入：任意类型
输出: True/False 或 None (无法转换)

如果已经是布尔值，直接返回
如果是字符串，兼容 "true" / "false" (不区分大小写、去掉空格)
其他字符串不接受 (例如 "yes" → None)
"""
def _coerce_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lower = value.strip().lower()
        if lower == "true":
            return True
        if lower == "false":
            return False
    return None

"""
a = [10, 20, 30]
for x in a:
    print(x)
# 10 20 30
for x in reversed(a):
    print(x)
# 30 20 10
"""

def _parse_state_json(text: str) -> Optional[Dict[str, bool]]:
    candidates = _extract_json_objects(text)  # 提取 [{JSON},{JSON},...,{JSON}] 列表 
    for raw in reversed(candidates):
        try:
            data = json.loads(raw)    # 如果 raw 是一个正确的 JSON 对象字符串，会把它解析成 Python 的 dict (JSON中true/false会变成Python的True/False)
        # 如果 raw 里用了 弯引号（“ ”）或者 True/False（大写）这种非 JSON 标准写法，会报错JSONDecodeError    
        except json.JSONDecodeError:
            continue
        """
        try: 里面放“可能会出错”的代码：这里 json.loads(raw) 可能因为 raw 不是合法 JSON 而报错
        except json.JSONDecodeError: 表示：如果 try 里抛出的错误类型是 json.JSONDecodeError (JSON 解析失败) ，就执行下面这一句
        continue 的意思是：跳过当前这轮循环，直接去处理下一个 raw (下一个候选 JSON 字符串)
        """

        """
        筛选: 要求 data 是 dict, 并且包含所有 REQUIRED_FIELDS 里的键
        """
        if not isinstance(data, dict):
            continue
        if not all(key in data for key in REQUIRED_FIELDS):
            continue
        
        parsed: Dict[str, bool] = {}  # 运行效果等价于parsed = {}, 类型提示：parsed 是 str→bool 的字典
        ok = True
        for key in REQUIRED_FIELDS:
            coerced = _coerce_bool(data.get(key))
            if coerced is None:
                ok = False
                break
            parsed[key] = coerced
        if ok:
            return parsed
    return None

# exact_match_score：单条样本的 0/1
# 这就是你要的“六个 state 全对才算 1，否则 0”
def exact_match_score(prediction_text: str, label_text: str) -> int:
    pred = _parse_state_json(prediction_text)
    label = _parse_state_json(label_text)
    if pred is None or label is None:
        return 0
    return 1 if all(pred[k] == label[k] for k in REQUIRED_FIELDS) else 0


def exact_match_accuracy(predictions: Iterable[str], labels: Iterable[str]) -> float:
    scores = [exact_match_score(p, l) for p, l in zip(predictions, labels)]
    if not scores:
        return 0.0
    return sum(scores) / len(scores)
