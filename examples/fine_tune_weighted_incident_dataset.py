from __future__ import annotations

import json

import torch
import torch.nn.functional as F
from datasets import load_dataset
from torch.utils.data import DataLoader
from transformers import (
    ProgressCallback,
    PrinterCallback,
    TrainingArguments,
    set_seed,
)

import llm_recovery.constants.constants as constants
from llm_recovery.fine_tuning.logging_callback import LoggingCallback
from llm_recovery.fine_tuning.lora import LORA
from llm_recovery.fine_tuning.weighted_examples_dataset import (
    TOKEN_WEIGHTS_KEY,
    WeightedExamplesDataset,
)
from llm_recovery.fine_tuning.weighted_trainer import WeightedLossTrainer
from llm_recovery.load_llm.load_llm import LoadLLM


class DebugWeightedLossTrainer(WeightedLossTrainer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._printed_training_loss_debug = False

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        token_weights = inputs.get(TOKEN_WEIGHTS_KEY)
        result = super().compute_loss(
            model,
            inputs,
            return_outputs=return_outputs,
            num_items_in_batch=num_items_in_batch,
        )

        if self.model.training and not self._printed_training_loss_debug and token_weights is not None:
            if return_outputs:
                weighted_loss, outputs = result
            else:
                weighted_loss = result
                outputs = model(
                    input_ids=inputs[constants.GENERAL.INPUT_IDS],
                    attention_mask=inputs[constants.GENERAL.ATTENTION_MASK],
                    labels=inputs[constants.GENERAL.LABELS],
                )

            labels = inputs[constants.GENERAL.LABELS]
            logits = outputs.logits
            shift_logits = logits[..., :-1, :].contiguous()
            shift_labels = labels[..., 1:].contiguous()
            shift_weights = token_weights[..., 1:].contiguous().to(shift_logits.device)

            per_token_loss = F.cross_entropy(
                shift_logits.view(-1, shift_logits.size(-1)),
                shift_labels.view(-1),
                reduction="none",
                ignore_index=-100,
            ).view_as(shift_labels)

            valid_mask = shift_labels != -100
            valid_losses = per_token_loss[valid_mask]
            valid_weights = shift_weights[valid_mask]
            unweighted_loss = valid_losses.mean()
            weighted_debug_loss = (valid_losses * valid_weights).sum() / valid_weights.sum()

            print("\n=== First Training Batch Loss Debug ===")
            print(f"trainer_logged_weighted_loss: {float(weighted_loss.item()):.6f}")
            print(f"manual_unweighted_loss:      {float(unweighted_loss.item()):.6f}")
            print(f"manual_weighted_loss:        {float(weighted_debug_loss.item()):.6f}")
            print(
                "training_batch weights min/max/mean: "
                f"{float(valid_weights.min().item()):.6f} / "
                f"{float(valid_weights.max().item()):.6f} / "
                f"{float(valid_weights.mean().item()):.6f}"
            )
            print(
                "training_batch per_token_loss mean/max: "
                f"{float(valid_losses.mean().item()):.6f} / "
                f"{float(valid_losses.max().item()):.6f}"
            )
            self._printed_training_loss_debug = True

        return result


def debug_compare_losses(model, dataset, tokenizer, n_samples: int = 1) -> None:
    loader = DataLoader(
        dataset,
        batch_size=n_samples,
        shuffle=False,
        collate_fn=dataset.collate,
    )
    batch = next(iter(loader))
    device = next(model.parameters()).device
    batch = {
        key: value.to(device) if torch.is_tensor(value) else value
        for key, value in batch.items()
    }

    model.eval()
    with torch.no_grad():
        token_weights = batch[TOKEN_WEIGHTS_KEY]
        inputs = {
            constants.GENERAL.INPUT_IDS: batch[constants.GENERAL.INPUT_IDS],
            constants.GENERAL.ATTENTION_MASK: batch[constants.GENERAL.ATTENTION_MASK],
            constants.GENERAL.LABELS: batch[constants.GENERAL.LABELS],
        }
        outputs = model(**inputs)
        unweighted_loss = outputs.loss

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
        weighted_loss = (per_token_loss * effective_weights).sum() / denom

        valid_positions = shift_labels != -100
        valid_losses = per_token_loss[valid_positions]
        valid_weights = effective_weights[valid_positions]
        valid_label_ids = shift_labels[valid_positions]

        print("\n=== Debug Loss Compare ===")
        print(f"unweighted_loss: {unweighted_loss.item():.6f}")
        print(f"weighted_loss:   {weighted_loss.item():.6f}")
        print(f"valid_tokens:    {valid_losses.numel()}")
        print(
            "token_weights min/max/mean: "
            f"{valid_weights.min().item():.6f} / "
            f"{valid_weights.max().item():.6f} / "
            f"{valid_weights.mean().item():.6f}"
        )
        print(
            "per_token_loss mean/max: "
            f"{valid_losses.mean().item():.6f} / "
            f"{valid_losses.max().item():.6f}"
        )
        print(f"effective_weights.sum(): {denom.item():.6f}")

        sample = dataset[0]
        prompt_token_count = int((sample[constants.GENERAL.LABELS] == -100).sum().item())
        answer_ids = sample[constants.GENERAL.INPUT_IDS][prompt_token_count:].tolist()
        answer_weights = sample[TOKEN_WEIGHTS_KEY][prompt_token_count:].tolist()
        answer_text = tokenizer.decode(answer_ids, skip_special_tokens=False)
        print("\n=== Answer Prefix (decoded) ===")
        print(answer_text[:2000])

        print("\n=== First 120 Answer Token Weights ===")
        print(answer_weights[:120])

        try:
            final_json_text, final_json_obj = dataset._extract_final_json(dataset.answers[0])
            print("\n=== Parsed Final JSON Keys ===")
            print(list(final_json_obj.keys()) if final_json_obj else None)
            if final_json_text and final_json_obj:
                spans = dataset._find_value_spans(final_json_text, final_json_obj)
                print("\n=== JSON Value Spans ===")
                print(json.dumps(spans, indent=2, ensure_ascii=False))
        except Exception as exc:
            print(f"\nJSON span parsing failed: {exc}")

        top_k = min(20, valid_losses.numel())
        top_values, top_indices = torch.topk(valid_losses, k=top_k)
        print("\n=== Top High-Loss Tokens ===")
        for rank, (loss_value, idx_tensor) in enumerate(zip(top_values, top_indices), start=1):
            idx = int(idx_tensor.item())
            token_id = int(valid_label_ids[idx].item())
            token_text = tokenizer.decode([token_id], skip_special_tokens=False)
            token_weight = float(valid_weights[idx].item())
            print(
                f"{rank:02d}. loss={float(loss_value.item()):.6f} "
                f"weight={token_weight:.3f} token_id={token_id} token={token_text!r}"
            )

    model.train()


if __name__ == "__main__":
    seed = 99125
    set_seed(seed)
    device_map = {"": 0}
    tokenizer, llm = LoadLLM.load_llm(
        llm_name=constants.LLM.DEEPSEEK_14B_QWEN,
        device_map=device_map
    )

    ds = load_dataset(
        "kimhammar/CSLE-IncidentResponse-V1",
        data_files="incident_examples.json"
    )
    train = ds["train"][0]
    instructions = train["instructions"][:20000]
    answers = train["answers"][:20000]

    field_weights = {
        "MITRE ATT&CK Tactics": 4.0,
        "Incident": 1.75,
        "Incident description": 0.35,
        "MITRE ATT&CK Techniques": 0.35,
        "Entities": 0.25,
    }

    lora_rank = 64
    lora_alpha = 128
    lora_dropout = 0.05
    llm = LORA.setup_llm_for_fine_tuning(
        llm=llm,
        r=lora_rank,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout
    )
    dataset = WeightedExamplesDataset(
        instructions=instructions,
        answers=answers,
        tokenizer=tokenizer,
        field_weights=field_weights,
        default_answer_weight=1.0,
        prompt_weight=0.0,
        max_length=4000,
    )

    output_dir = "/content/drive/MyDrive/weighted_incident"
    lr = 0.00095
    per_device_batch_size = 1
    num_train_epochs = 1
    prompt_logging_frequency = 50
    max_generation_tokens = 3000
    logging_steps = 1
    running_average_window = 100
    temperature = 0.6
    save_steps = 25
    save_limit = 3
    gradient_accumulation_steps = 32
    progress_save_frequency = 10
    # RESUME = "/content/drive/MyDrive/weighted incident/checkpoint-250"
    # resume_from_checkpoint=RESUME/None

    args = TrainingArguments(
        output_dir=output_dir,
        bf16=True,
        per_device_train_batch_size=per_device_batch_size,
        num_train_epochs=num_train_epochs,
        learning_rate=lr,
        logging_steps=logging_steps,
        # remove_unused_columns=False,  # key point
        save_strategy=constants.LORA.SAVE_STRATEGY_STEPS,
        save_steps=save_steps,
        save_total_limit=save_limit,
        gradient_accumulation_steps=gradient_accumulation_steps,
        seed=seed,
    )

    callback = LoggingCallback(
        prompts=instructions,
        answers=answers,
        tokenizer=tokenizer,
        dataset=dataset,
        window=running_average_window,
        gen_kwargs=dict(max_new_tokens=max_generation_tokens, temperature=temperature, do_sample=True),
        prompt_logging=True,
        prompt_logging_frequency=prompt_logging_frequency,
        progress_save_frequency=progress_save_frequency,
        seed=seed,
    )

    trainer = DebugWeightedLossTrainer(
        model=llm,
        args=args,
        train_dataset=dataset,
        data_collator=dataset.collate,
        callbacks=[callback],
    )
    trainer.remove_callback(PrinterCallback)
    trainer.remove_callback(ProgressCallback)
    debug_compare_losses(llm, dataset, tokenizer, n_samples=1)
    trainer.train()
    trainer.save_model(output_dir=args.output_dir)
