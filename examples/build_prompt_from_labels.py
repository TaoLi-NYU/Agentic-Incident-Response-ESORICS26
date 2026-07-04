import argparse
import random
from pathlib import Path
from typing import Dict, List


ACTION_PROMPT_TEMPLATE = (
    "Below is a system description, a sequence of network logs (e.g., from an intrusion detection system), "
    "a description of a cybersecurity incident, the current state of the recovery from the incident, "
    "a list of previously executed recovery actions, "
    "and an instruction that describes a task.\n"
    "Write a response that appropriately completes the request.\nBefore generating the response, "
    "think carefully about the system, the logs, and the instruction, then create a step-by-step "
    "chain of thoughts to ensure a logical and accurate response.\n\n"
    "### System:\n{}\n\n"
    "### Logs:\n{}\n\n"
    "### Incident:\n{}\n\n"
    "### State:\n{}\n"
    "The meaning of the state fields are as follows.\n"
    "is_attack_contained: Has the immediate threat been stopped from spreading?\n"
    "is_knowledge_sufficient: Have we gathered enough data to effectively contain and eradicate the attack?\n"
    "are_forensics_preserved: Has evidence been captured and stored in a forensically sound manner?\n"
    "is_eradicated: Is the adversary completely removed from the system?\n"
    "is_hardened: Has the root cause of the attack been remediated? i.e., are future attacks of the same "
    "type prevented?\n"
    "is_recovered: Are primary services restored for users?\n\n"
    "### Previous recovery actions:\n{}\n\n"
    "### Instruction:\n"
    "You are a security operator with advanced knowledge in cybersecurity "
    "and IT systems. You have been given information about a security incident and should"
    " generate the next suitable action for recovering the system from the incident. "
    "Your suggested action should be based on the logs, the system description only, the current state, and the "
    "previous recovery actions.\n"
    "Make sure that the suggested recovery action is consistent with the system description and the logs and that "
    "you do not repeat any action that has already been performed.\n"
    "The goal when selecting the recovery action is to change the state so that one of the state-properties that "
    "is currently 'false' "
    "becomes 'true'. The ideal recovery action sequence is: 1. contain the attack 2. gather information 3. "
    "preserve evidence "
    "4. eradicate the attacker 5. harden the system 6. recover operational services.\n"
    "When selecting the recovery action, make sure that it is concrete and actionable and minimizes unnecessary "
    "service disruptions. "
    "Vague or unnecessary actions will not change the state and should be avoided.\n"
    "Return a JSON object with two properties: 'Action' and 'Explanation', both of which should be strings.\n"
    "The property 'Action' should be a string that concisely describes the concrete recovery action.\n"
    "The property 'Explanation' should be a string that concisely explains why you selected the recovery action "
    "and motivates why the action is needed.\n\n"
    "### Response:\n<think>"
)


def _start_object() -> Dict[str, object]:
    return {
        "System": "",
        "Logs": [],
        "Incident": "",
        "Incident description": "",
        "Recovery actions": [],
    }


def _normalize_key(key: str) -> str:
    if key == "system":
        return "System"
    return key


def parse_labels_file(path: Path) -> List[Dict[str, object]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    objects: List[Dict[str, object]] = []
    cur: Dict[str, object] | None = None

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("{"):
            cur = _start_object()
            i += 1
            continue
        if stripped.startswith("}"):
            if cur is not None:
                objects.append(cur)
            cur = None
            i += 1
            continue
        if cur is None:
            i += 1
            continue

        if stripped.startswith('"') and ":" in stripped:
            key_part, rest = stripped.split(":", 1)
            key = _normalize_key(key_part.strip().strip('"'))
            rest = rest.strip()

            if key == "Logs":
                if "[" in rest:
                    i += 1
                    while i < len(lines):
                        item_line = lines[i].strip()
                        if item_line.startswith("]"):
                            break
                        if item_line.startswith('"'):
                            item = item_line.rstrip(",")
                            if item.startswith('"') and item.endswith('"'):
                                item = item[1:-1]
                            cur["Logs"].append(item)
                        i += 1
                    i += 1
                    continue

            if key == "Recovery actions":
                if rest.startswith("[]"):
                    cur["Recovery actions"] = []
                    i += 1
                    continue
                if rest.startswith("["):
                    i += 1
                    while i < len(lines):
                        item_line = lines[i].strip()
                        if item_line.startswith("]"):
                            break
                        if item_line.startswith('"'):
                            item = item_line.rstrip(",")
                            if item.startswith('"') and item.endswith('"'):
                                item = item[1:-1]
                            cur["Recovery actions"].append(item)
                        i += 1
                    i += 1
                    continue

            if rest.startswith('"'):
                # Single-line string
                if rest.count('"') >= 2 and rest.endswith('"'):
                    value = rest.rstrip(",")[1:-1]
                    cur[key] = value
                    i += 1
                    continue
                # Multi-line string; collect until next key or object end
                buf = [rest.lstrip('"')]
                i += 1
                while i < len(lines):
                    next_line = lines[i]
                    if next_line.strip().startswith('"') and ":" in next_line:
                        i -= 1
                        break
                    buf.append(next_line)
                    if next_line.rstrip().endswith('"'):
                        break
                    i += 1
                value = "\n".join(buf).rstrip(",")
                if value.endswith('"'):
                    value = value[:-1]
                cur[key] = value
                i += 1
                continue

        i += 1

    return objects


def build_prompt(sample: Dict[str, object]) -> str:
    state_json = (
        '{\n'
        '    "is_attack_contained": false,\n'
        '    "is_knowledge_sufficient": false,\n'
        '    "are_forensics_preserved": false,\n'
        '    "is_eradicated": false,\n'
        '    "is_hardened": false,\n'
        '    "is_recovered": false\n'
        '}'
    )

    logs = "\n".join(sample.get("Logs", [])).strip()
    incident_desc = str(sample.get("Incident description", "")).strip()
    system = str(sample.get("System", "")).strip()
    previous_actions = "None."

    return ACTION_PROMPT_TEMPLATE.format(
        system,
        logs,
        incident_desc,
        state_json,
        previous_actions,
    ).strip()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sample an Incident=Yes entry from labels.json and build an action prompt."
    )
    parser.add_argument(
        "--labels",
        required=True,
        help="Path to labels.json (may be non-standard JSON with multiline strings).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducible sampling.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write the generated prompt.",
    )
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    objects = parse_labels_file(Path(args.labels))
    incident_yes = [
        obj
        for obj in objects
        if str(obj.get("Incident", "")).strip().lower() == "yes"
    ]
    if not incident_yes:
        raise SystemExit("No Incident=Yes entries found.")

    sample = random.choice(incident_yes)
    prompt = build_prompt(sample)

    if args.output:
        Path(args.output).write_text(prompt, encoding="utf-8")
    else:
        print(prompt)


if __name__ == "__main__":
    main()
