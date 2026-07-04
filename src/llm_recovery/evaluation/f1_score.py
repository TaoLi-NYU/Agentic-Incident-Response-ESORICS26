from __future__ import annotations
from typing import Dict, Iterable
from llm_recovery.evaluation.exact_match import REQUIRED_FIELDS, _parse_state_json

"""
为什么 safe
如果某个 label 从来没出现过正例，导致 tp=fp=fn=0, 分母为 0, 就返回 0.0 避免报错
"""

def _safe_f1(tp: int, fp: int, fn: int) -> float:
    denom = 2 * tp + fp + fn
    return 0.0 if denom == 0 else (2 * tp) / denom


def multilabel_f1_from_texts(
    predictions: Iterable[str],
    labels: Iterable[str],
) -> Dict[str, float]:        # 表示函数multilabel_f1_from_texts返回一个字典
    counts: Dict[str, Dict[str, int]] = {
        k: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for k in REQUIRED_FIELDS  # 初始化计数器
    }

    for pred_text, label_text in zip(predictions, labels):
        label = _parse_state_json(label_text)
        if label is None:
            # Skip samples with invalid labels to avoid polluting metrics.
            continue
        
        """
        prediction 解析失败时，不跳过，而是把它当成全 False
        这会强烈惩罚模型：如果真实里某些字段是 True, 那么会产生 FN

        FP = 0, FN = 0 (关键！)
        micro/macro F1 的分子分母都不受影响 (因为 F1 只看 TP/FP/FN, 不看 TN)
        也就是说：这条样本对 F1 没有惩罚 (甚至你也可以说“没贡献”)
        这不是 bug, 而是 F1 指标本身的特性：它对大量 TN “不敏感”
        """
        pred = _parse_state_json(pred_text)
        if pred is None:
            # Treat invalid predictions as all-false.
            pred = {k: False for k in REQUIRED_FIELDS}

        for k in REQUIRED_FIELDS:
            p = pred[k]
            l = label[k]
            if p and l:
                counts[k]["tp"] += 1
            elif p and not l:
                counts[k]["fp"] += 1
            elif (not p) and l:
                counts[k]["fn"] += 1
            else:
                counts[k]["tn"] += 1
    """
    先对每个字段独立算一个 F1 (6 个 F1)
    再平均（每个字段权重一样），得到 macro F1
    """
    per_label_f1 = {
        k: _safe_f1(counts[k]["tp"], counts[k]["fp"], counts[k]["fn"])
        for k in REQUIRED_FIELDS
    }
    macro_f1 = sum(per_label_f1.values()) / len(REQUIRED_FIELDS)

    """
    把所有字段的 TP/FP/FN 全加在一起，当成一个大池子
    再算一个整体 F1
    """
    tp_total = sum(counts[k]["tp"] for k in REQUIRED_FIELDS)
    fp_total = sum(counts[k]["fp"] for k in REQUIRED_FIELDS)
    fn_total = sum(counts[k]["fn"] for k in REQUIRED_FIELDS)
    micro_f1 = _safe_f1(tp_total, fp_total, fn_total)

    return {
        "micro_f1": micro_f1,
        "macro_f1": macro_f1,
        "per_label_f1": per_label_f1,
    }