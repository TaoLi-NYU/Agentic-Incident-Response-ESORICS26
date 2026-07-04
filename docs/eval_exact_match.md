# Exact Match 评估说明

本文说明 `src/llm_recovery/evaluation/exact_match.py` 的用途、逻辑和为什么要新增。

## 代码在做什么

该模块为“预测下一恢复状态”的 JSON 输出提供 **exact match** 评估。
模型输出是自由文本，可能包含 `<think>...</think>` 或其他解释性文字，所以该模块会从文本中提取 JSON，再与标签 JSON 做严格匹配。

核心规则：
- 必须包含以下 6 个布尔字段：
  - is_attack_contained
  - is_knowledge_sufficient
  - are_forensics_preserved
  - is_eradicated
  - is_hardened
  - is_recovered
- **六个字段全部一致才算该样本正确（记 1）**。
- 任何解析失败、字段缺失、或字段值不一致都记 0。
- 最终 accuracy = 所有样本 0/1 的平均值。

## 如何处理模型输出文本

模型输出不一定是纯 JSON，本模块做了更稳健的解析：
- 扫描文本中所有 `{ ... }` 的 JSON 候选块（处理嵌套花括号，忽略引号中的括号）。
- **从最后一个 JSON 块开始尝试解析**，因为最终答案通常在末尾。
- 字段值既接受 JSON 布尔值，也接受字符串形式的 "true" / "false"。

关键函数：
- `_extract_json_objects(text)`
  - 从文本中提取所有可能的 JSON 块。
- `_parse_state_json(text)`
  - 解析最后一个完整、包含 6 字段的 JSON。
- `exact_match_score(prediction_text, label_text)`
  - 单样本评估，完全匹配返回 1，否则 0。
- `exact_match_accuracy(predictions, labels)`
  - 对一批样本计算平均准确率。

## 为什么要新增

你需要在 LoRA 训练完成后，对测试集（如 500 条）评估 **exact match accuracy**。
而模型输出包含 `<think>` 或其他说明文字，直接 `json.loads` 容易失败。
因此新增该模块来：
- 在带解释文本的输出中稳定提取 JSON。
- 严格执行你定义的 6 字段全匹配规则。
- 让评估逻辑可复用，避免在脚本中反复手写解析。
