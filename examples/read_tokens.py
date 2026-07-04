from __future__ import annotations

import argparse
import sys
from pathlib import Path

from llm_recovery.load_llm.load_llm import LoadLLM
import llm_recovery.constants.constants as constants


def read_text(path: str) -> str:
    if path == '-':
        return sys.stdin.read()
    return Path(path).read_text(encoding='utf-8')


def main() -> int:
    parser = argparse.ArgumentParser(description='Count tokens with the project LLM tokenizer')
    parser.add_argument(
        'text_path',
        nargs='?',
        default=r'D:\RA Project\AI Agent&Cybersecurity paper\llm_recovery\examples\sample_text.txt',
        help='Path to text file, or - to read from stdin',
    )
    parser.add_argument('--model', default=constants.LLM.DEEPSEEK_1_5B_QWEN,
                        help='Model name/path for LoadLLM')
    parser.add_argument('--device-map', default=constants.GPU.AUTO,
                        help='Device map for LoadLLM')
    parser.add_argument('--no-special-tokens', action='store_true',
                        help='Disable add_special_tokens')
    args = parser.parse_args()

    tokenizer, _ = LoadLLM.load_llm(llm_name=args.model, device_map=args.device_map)
    text = read_text(args.text_path)
    add_special = not args.no_special_tokens
    ids = tokenizer(text, add_special_tokens=add_special)['input_ids']
    print(len(ids))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
