from __future__ import annotations

import torch
import torch.nn.functional as F
from transformers import Trainer

import llm_recovery.constants.constants as constants
from llm_recovery.fine_tuning.weighted_examples_dataset import TOKEN_WEIGHTS_KEY


class WeightedLossTrainer(Trainer):
    """
    Trainer with optional per-token weighted causal LM loss.
    """

    def _set_signature_columns_if_needed(self):
        super()._set_signature_columns_if_needed()
        if self._signature_columns is None:
            self._signature_columns = []
        if TOKEN_WEIGHTS_KEY not in self._signature_columns:
            self._signature_columns.append(TOKEN_WEIGHTS_KEY)

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        token_weights = inputs.pop(TOKEN_WEIGHTS_KEY, None)
        outputs = model(**inputs)

        if token_weights is None:
            loss = outputs.loss
            return (loss, outputs) if return_outputs else loss

        logits = outputs.logits
        labels = inputs[constants.GENERAL.LABELS]

        shift_logits = logits[..., :-1, :].contiguous()
        shift_labels = labels[..., 1:].contiguous()
        shift_weights = token_weights[..., 1:].contiguous().to(shift_logits.device)

        per_token_loss = F.cross_entropy(
            shift_logits.view(-1, shift_logits.size(-1)),
            shift_labels.view(-1),
            reduction="none",
            ignore_index=-100,
        ).view_as(shift_labels)

        valid_mask = (shift_labels != -100).to(shift_logits.dtype)
        effective_weights = shift_weights * valid_mask
        denom = effective_weights.sum()
        if float(denom.item()) <= 0.0:
            loss = per_token_loss.sum() * 0.0
        else:
            loss = (per_token_loss * effective_weights).sum() / denom

        return (loss, outputs) if return_outputs else loss
