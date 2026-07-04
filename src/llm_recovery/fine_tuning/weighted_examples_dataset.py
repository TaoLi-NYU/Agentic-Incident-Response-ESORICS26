from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import torch
from torch.utils.data import Dataset
from transformers import PreTrainedTokenizer

import llm_recovery.constants.constants as constants


TOKEN_WEIGHTS_KEY = "token_weights"
DEFAULT_FIELD_WEIGHTS: Dict[str, float] = {
    "Incident": 1.5,
    "MITRE ATT&CK Tactics": 3.0,
    "Incident description": 0.3,
    "MITRE ATT&CK Techniques": 0.3,
    "Entities": 0.3,
}


class WeightedExamplesDataset(Dataset[Dict[str, torch.Tensor]]):
    """
    Prompt-answer dataset with per-token loss weights on answer fields.
    """

    def __init__(
        self,
        instructions: List[str],
        answers: List[str],
        tokenizer: PreTrainedTokenizer,
        field_weights: Optional[Dict[str, float]] = None,
        default_answer_weight: float = 1.0,
        prompt_weight: float = 0.0,
        max_length: int = 256,
    ) -> None:
        self.instructions = instructions
        self.answers = answers
        self.tokenizer = tokenizer
        self.field_weights = dict(DEFAULT_FIELD_WEIGHTS)
        if field_weights:
            self.field_weights.update(field_weights)
        self.default_answer_weight = float(default_answer_weight)
        self.prompt_weight = float(prompt_weight)
        self.max_length = int(max_length)

    def __len__(self) -> int:
        return len(self.instructions)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        prompt = self.instructions[idx]
        answer = self.answers[idx]

        prompt_tokens = self.tokenizer(
            prompt,
            add_special_tokens=False,
            truncation=True,
            max_length=self.max_length,
        )
        answer_tokens = self.tokenizer(
            answer,
            add_special_tokens=False,
            truncation=True,
            max_length=self.max_length,
            return_offsets_mapping=True,
        )

        prompt_ids = prompt_tokens[constants.GENERAL.INPUT_IDS]
        answer_ids = answer_tokens[constants.GENERAL.INPUT_IDS]
        prompt_mask = prompt_tokens[constants.GENERAL.ATTENTION_MASK]
        answer_mask = answer_tokens[constants.GENERAL.ATTENTION_MASK]

        input_ids = prompt_ids + answer_ids
        attention_mask = prompt_mask + answer_mask
        labels = [-100] * len(prompt_ids) + answer_ids

        answer_weights = self._build_answer_token_weights(answer, answer_tokens)
        token_weights = [self.prompt_weight] * len(prompt_ids) + answer_weights

        return {
            constants.GENERAL.INPUT_IDS: torch.tensor(input_ids, dtype=torch.long),
            constants.GENERAL.ATTENTION_MASK: torch.tensor(attention_mask, dtype=torch.long),
            constants.GENERAL.LABELS: torch.tensor(labels, dtype=torch.long),
            TOKEN_WEIGHTS_KEY: torch.tensor(token_weights, dtype=torch.float),
        }

    def collate(self, batch: List[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
        input_ids = [b[constants.GENERAL.INPUT_IDS] for b in batch]
        attention_mask = [b[constants.GENERAL.ATTENTION_MASK] for b in batch]
        labels = [b[constants.GENERAL.LABELS] for b in batch]
        token_weights = [b[TOKEN_WEIGHTS_KEY] for b in batch]

        input_ids_tensor = torch.nn.utils.rnn.pad_sequence(
            input_ids,
            batch_first=True,
            padding_value=self.tokenizer.pad_token_id,
        )
        attention_mask_tensor = torch.nn.utils.rnn.pad_sequence(
            attention_mask,
            batch_first=True,
            padding_value=0,
        )
        labels_tensor = torch.nn.utils.rnn.pad_sequence(
            labels,
            batch_first=True,
            padding_value=-100,
        )
        token_weights_tensor = torch.nn.utils.rnn.pad_sequence(
            token_weights,
            batch_first=True,
            padding_value=0.0,
        )
        return {
            constants.GENERAL.INPUT_IDS: input_ids_tensor,
            constants.GENERAL.ATTENTION_MASK: attention_mask_tensor,
            constants.GENERAL.LABELS: labels_tensor,
            TOKEN_WEIGHTS_KEY: token_weights_tensor,
        }

    def _build_answer_token_weights(
        self,
        answer: str,
        answer_tokens: Dict[str, Any],
    ) -> List[float]:
        offsets = answer_tokens.get("offset_mapping")
        if offsets is None:
            return [self.default_answer_weight] * len(answer_tokens[constants.GENERAL.INPUT_IDS])

        weights = [self.default_answer_weight] * len(offsets)
        final_json_text, final_obj = self._extract_final_json(answer)
        if final_json_text is None or final_obj is None:
            return weights

        spans = self._find_value_spans(final_json_text, final_obj)
        for field_name, (start_char, end_char) in spans.items():
            field_weight = self.field_weights.get(field_name)
            if field_weight is None:
                continue
            for i, offset in enumerate(offsets):
                token_start, token_end = int(offset[0]), int(offset[1])
                if token_end <= start_char or token_start >= end_char:
                    continue
                weights[i] = float(field_weight)
        return weights

    @staticmethod
    def _extract_final_json(answer: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        decoder = json.JSONDecoder()
        matches = list(re.finditer(r"\{", answer))
        for match in reversed(matches):
            candidate = answer[match.start():]
            try:
                obj, end = decoder.raw_decode(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and "MITRE ATT&CK Tactics" in obj:
                return candidate[:end], obj
        return None, None

    @staticmethod
    def _find_value_spans(json_text: str, obj: Dict[str, Any]) -> Dict[str, Tuple[int, int]]:
        spans: Dict[str, Tuple[int, int]] = {}
        cursor = 0
        for key, value in obj.items():
            key_pattern = re.escape(json.dumps(str(key), ensure_ascii=False))
            key_match = re.search(key_pattern + r"\s*:\s*", json_text[cursor:])
            if key_match is None:
                continue
            value_start = cursor + key_match.end()
            value_text = json.dumps(value, ensure_ascii=False)
            if not json_text.startswith(value_text, value_start):
                alt_start = json_text.find(value_text, value_start)
                if alt_start == -1:
                    continue
                value_start = alt_start
            value_end = value_start + len(value_text)
            spans[str(key)] = (value_start, value_end)
            cursor = value_end
        return spans
