import json


def load_json(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"[JSON] Successfully loaded {len(data)} records from {filepath}")
        return data
    except FileNotFoundError:
        print(f"[JSON] Error: File {filepath} not found.")
        return []


if __name__ == '__main__':
    json_data = load_json(
        r"D:\RA Project\AI Agent&Cybersecurity paper\updated_data\transformed_dataset_cls_pri_all2preprocessing.json"
    )
    if not json_data:
        raise SystemExit(1)

    if not isinstance(json_data, list):
        print("Unexpected JSON type:", type(json_data).__name__)
        raise SystemExit(1)

    item = json_data[0]

    def escape_newlines(s: str) -> str:
        return s.replace("\\", "\\\\").replace("\n", "\\n")

    instruction = item.get("instruction", "")
    output = item.get("output", "")

    print("{")
    print('  "instruction": "' + escape_newlines(instruction) + '",')
    print('  "output": "' + escape_newlines(output) + '"')
    print("}")
