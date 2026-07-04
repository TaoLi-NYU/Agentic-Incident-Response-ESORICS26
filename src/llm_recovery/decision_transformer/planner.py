from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Sequence, Tuple

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, PreTrainedModel, PreTrainedTokenizer

import llm_recovery.constants.constants as constants
from llm_recovery.evaluation.exact_match import _parse_state_json


RECOVERY_STATE_FIELDS: Tuple[str, ...] = (
    "is_attack_contained",
    "is_knowledge_sufficient",
    "are_forensics_preserved",
    "is_eradicated",
    "is_hardened",
    "is_recovered",
)

TERMINAL_STATE: Tuple[bool, ...] = (True, True, True, True, True, True)


def _state_dict_to_tuple(state: dict) -> Tuple[bool, ...]:
    return tuple(bool(state[field]) for field in RECOVERY_STATE_FIELDS)


def _state_tuple_to_dict(state: Sequence[bool]) -> dict:
    return {field: bool(state[i]) for i, field in enumerate(RECOVERY_STATE_FIELDS)}


def _extract_tagged(text: str, open_tag: str, close_tag: str) -> Optional[str]:
    if open_tag not in text:
        return None
    start = text.index(open_tag) + len(open_tag)
    if close_tag in text[start:]:
        end = text.index(close_tag, start)
        return text[start:end].strip()
    return text[start:].strip()


@dataclass(frozen=True)
class PlannerConfig:
    num_candidates: int = 3
    num_rollout_samples: int = 3
    max_plan_steps: int = 25
    max_rollout_depth: int = 25
    action_max_new_tokens: int = 128
    state_max_new_tokens: int = 128
    candidate_temperature: float = 0.7
    candidate_top_p: float = 0.9
    rollout_temperature: float = 0.7
    rollout_top_p: float = 0.9


ActionPromptBuilder = Callable[[str, Sequence[bool]], str]
StatePromptBuilder = Callable[[str, Sequence[bool], str], str]


def default_action_prompt(logs: str, state: Sequence[bool]) -> str:
    state_json = json.dumps(_state_tuple_to_dict(state), ensure_ascii=True)
    parts = [
        f"{constants.DECISION_TRANSFORMER.TASK_DESCRIPTION_OPEN_DELIMITER}"
        f"{constants.DECISION_TRANSFORMER.TASK_INSTRUCTION}"
        f"{constants.DECISION_TRANSFORMER.TASK_DESCRIPTION_CLOSE_DELIMITER}",
        "Current recovery state:",
        state_json,
        "Incident logs:",
        logs,
        "Generate the next response action. If possible, wrap it in "
        f"{constants.DECISION_TRANSFORMER.ACTION_OPEN_DELIMITER}...{constants.DECISION_TRANSFORMER.ACTION_CLOSE_DELIMITER}.",
    ]
    return "\n".join(parts)


def default_state_prompt(logs: str, state: Sequence[bool], action: str) -> str:
    state_json = json.dumps(_state_tuple_to_dict(state), ensure_ascii=True)
    parts = [
        "You are assessing the incident response status.",
        "Current recovery state:",
        state_json,
        "Selected action:",
        action,
        "Incident logs:",
        logs,
        "Predict the next recovery state as JSON with keys: "
        + ", ".join(RECOVERY_STATE_FIELDS)
        + ".",
    ]
    return "\n".join(parts)


class IncidentResponsePlanner:
    """
    Planning algorithm (Alg. 1) for incident response using a fine-tuned LLM.
    """

    def __init__(
        self,
        llm: PreTrainedModel,
        tokenizer: PreTrainedTokenizer,
        *,
        config: Optional[PlannerConfig] = None,
        action_prompt_builder: ActionPromptBuilder = default_action_prompt,
        state_prompt_builder: StatePromptBuilder = default_state_prompt,
    ) -> None:
        self.llm = llm
        self.tokenizer = tokenizer
        self.config = config or PlannerConfig()
        self.action_prompt_builder = action_prompt_builder
        self.state_prompt_builder = state_prompt_builder

        if self.tokenizer.pad_token_id is None:
            self.tokenizer.pad_token_id = self.tokenizer.eos_token_id

    def plan(self, logs: str) -> List[str]:
        state = (False, False, False, False, False, False)
        plan: List[str] = []
        t = 0

        while state != TERMINAL_STATE and t < self.config.max_plan_steps:
            actions = self._sample_actions(logs, state, self.config.num_candidates)
            if not actions:
                break

            scores = [
                self._estimate_recovery_time(logs, state, action)
                for action in actions
            ]

            best_idx = min(range(len(actions)), key=lambda i: scores[i])
            best_action = actions[best_idx]
            plan.append(best_action)

            next_state = self._predict_state(logs, state, best_action)
            if next_state is None:
                break
            state = next_state
            t += 1

        return plan

    def _generate_text(
        self,
        prompt: str,
        max_new_tokens: int,
        temperature: float,
        top_p: float,
    ) -> str:
        gen = self.tokenizer(prompt, return_tensors=constants.GENERAL.PYTORCH).to(
            self.llm.device
        )
        do_sample = temperature > 0.0
        out = self.llm.generate(
            **gen,
            max_new_tokens=max_new_tokens,
            do_sample=do_sample,
            temperature=temperature if do_sample else None,
            top_p=top_p if do_sample else None,
            eos_token_id=self.tokenizer.eos_token_id,
            pad_token_id=self.tokenizer.pad_token_id,
        )
        text = str(self.tokenizer.decode(out[0], skip_special_tokens=True))
        if text.startswith(prompt):
            text = text[len(prompt) :]
        return text.strip()

    def _sample_actions(
        self, logs: str, state: Sequence[bool], num_actions: int
    ) -> List[str]:
        prompt = self.action_prompt_builder(logs, state)
        actions: List[str] = []
        attempts = 0
        max_attempts = max(num_actions * 3, num_actions)

        while len(actions) < num_actions and attempts < max_attempts:
            attempts += 1
            text = self._generate_text(
                prompt,
                max_new_tokens=self.config.action_max_new_tokens,
                temperature=self.config.candidate_temperature,
                top_p=self.config.candidate_top_p,
            )
            action = _extract_tagged(
                text,
                constants.DECISION_TRANSFORMER.ACTION_OPEN_DELIMITER,
                constants.DECISION_TRANSFORMER.ACTION_CLOSE_DELIMITER,
            ) or text
            action = action.strip()
            if action and action not in actions:
                actions.append(action)
        return actions

    def _predict_state(
        self, logs: str, state: Sequence[bool], action: str
    ) -> Optional[Tuple[bool, ...]]:
        prompt = self.state_prompt_builder(logs, state, action)
        text = self._generate_text(
            prompt,
            max_new_tokens=self.config.state_max_new_tokens,
            temperature=self.config.rollout_temperature,
            top_p=self.config.rollout_top_p,
        )
        parsed = _parse_state_json(text)
        if parsed is None:
            return None
        return _state_dict_to_tuple(parsed)

    def _estimate_recovery_time(
        self, logs: str, state: Sequence[bool], action: str
    ) -> float:
        samples = [
            self._recovery_time(logs, state, action, depth=0)
            for _ in range(self.config.num_rollout_samples)
        ]
        return float(sum(samples)) / float(len(samples))

    def _recovery_time(
        self, logs: str, state: Sequence[bool], action: str, depth: int
    ) -> int:
        if depth >= self.config.max_rollout_depth:
            return self.config.max_rollout_depth

        next_state = self._predict_state(logs, state, action)
        if next_state is None:
            return self.config.max_rollout_depth
        if next_state == TERMINAL_STATE:
            return 1

        next_actions = self._sample_actions(logs, next_state, 1)
        if not next_actions:
            return self.config.max_rollout_depth
        return 1 + self._recovery_time(
            logs, next_state, next_actions[0], depth=depth + 1
        )


if __name__ == "__main__":
    print("Loading the fine-tuned incident response LLM.")
    model = AutoModelForCausalLM.from_pretrained(
        "kimhammar/LLMIncidentResponse",
        device_map="auto",
        torch_dtype=torch.float16,
    )
    tokenizer = AutoTokenizer.from_pretrained("kimhammar/LLMIncidentResponse")
    print(f"LLM loaded successfully on device: {model.device}")
