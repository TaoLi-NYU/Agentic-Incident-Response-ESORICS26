# examples/inspect_dataset.py
from datasets import load_dataset


def main():
    # 只加载 examples_16_june.json 这一份
    ds = load_dataset(
        "kimhammar/CSLE-IncidentResponse-V1",
        data_files="examples_16_june.json"
    )

    # 取 train 里的第 0 条样本
    sample = ds["train"][0]

    print("这一条样本的字段：", sample.keys(), "\n")

    instructions = sample["instructions"]
    answers = sample["answers"]

    print("instructions 类型：", type(instructions))
    print("instructions 长度：", len(instructions))
    print("\n第1条 instruction: \n", instructions[0])

    print("\n" + "-" * 80 + "\n")

    print("answers 类型：", type(answers))
    print("answers 长度：", len(answers))
    print("\n第1条 answer: \n", answers[0])


if __name__ == "__main__":
    main()
