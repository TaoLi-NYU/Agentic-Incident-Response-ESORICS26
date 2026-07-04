import json
import matplotlib.pyplot as plt


path = r"D:\RA Project\AI Agent&Cybersecurity paper\llm_recovery\transformed-dataset-lora\checkpoint-7430\trainer_state.json"

with open(path, "r") as f:
    state = json.load(f)

# 过滤出带 loss 的记录
log_history = state.get("log_history", [])
steps = []
losses = []

for item in log_history:
    if "loss" in item and "step" in item:
        steps.append(item["step"])
        losses.append(item["loss"])

plt.plot(steps, losses, label="loss")
plt.xlabel("step")
plt.ylabel("loss")
plt.legend()
plt.show()
