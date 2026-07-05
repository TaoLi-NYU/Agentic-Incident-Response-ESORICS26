# Agentic-Incident-Response-ESORICS26
About Artifacts for the paper "Agentic Incident Response through Multiscale Planning with a Digital Twin"


## Digital-Twin Topology
<img width="946" height="328" alt="image" src="https://github.com/user-attachments/assets/be5265c9-b8f3-481d-b9ad-e8bc98efb37f" />

(Left) The digital twin is a virtual replica of the affected system, which
offers a safe environment for investigating the incident and testing response
actions. (Right) The network digital twin configuration adopted in our testbed.

## Artifacts

- The incident-response fine-tuning dataset used in our experiments is available on
  [Hugging Face](https://huggingface.co/datasets/kimhammar/CSLE-IncidentResponse-V1/tree/main).

- The LoRA adapter weights of our fine-tuned model are available on
  [Hugging Face](https://huggingface.co/GYR1-determine/llmagent4incident-response).

## Attack Scenarios

The digital-twin experiments evaluate the incident-response framework under
three multi-stage attack scenarios of increasing scope and technique diversity.

| Scenario | Compromised servers | Main techniques |
|---|---:|---|
| **Weak-Credential-3** | 3 | SSH weak credentials, anonymous SMB access, and Shellshock exploitation |
| **Shellshock-4** | 4 | SSH password spraying, anonymous SMB access, Shellshock exploitation, and unauthorized HTTP upload |
| **Command-Injection-5** | 5 | SSH credential reuse, SMB staging, Shellshock exploitation, and diagnostic-service command injection |

The corresponding attack scripts and experiment inputs are:

- **Weak-Credential-3**: [`run_attack.py`](llm_ir_dt_new/run_attack.py),
  [`system.txt`](llm_ir_dt_new/inputs/system.txt),
  [`logs.txt`](llm_ir_dt_new/inputs/logs.txt), and
  [`incident.txt`](llm_ir_dt_new/inputs/incident.txt).
- **Shellshock-4**: [`run_attack_four_servers_diverse.py`](llm_ir_dt_new/run_attack_four_servers_diverse.py),
  [`logs_four_servers_diverse.txt`](llm_ir_dt_new/inputs/logs_four_servers_diverse.txt), and
  [`incident_four_servers_diverse.txt`](llm_ir_dt_new/inputs/incident_four_servers_diverse.txt).
- **Command-Injection-5**: [`run_attack_five_servers_diverse.py`](llm_ir_dt_new/run_attack_five_servers_diverse.py),
  [`logs_5_servers_diverse.txt`](llm_ir_dt_new/inputs/logs_5_servers_diverse.txt), and
  [`incident_5_servers_diverse.txt`](llm_ir_dt_new/inputs/incident_5_servers_diverse.txt).

## Experimental Environment

Offline fine-tuning was performed on a Google Cloud virtual machine with one
NVIDIA A100 GPU. The experiments use the
`DeepSeek-R1-Distill-Qwen-14B` base model with LoRA fine-tuning.

| Parameter | Value |
|---|---:|
| Cloud platform | Google Cloud |
| Machine type | `a2-highgpu-1g` |
| Provisioning model | Spot VM |
| Region | `us-central1` |
| GPU | 1 × NVIDIA A100 40 GB |
| Operating system | Ubuntu 22.04 LTS |
| Boot disk | 200 GB balanced persistent disk |
| Base model | DeepSeek-R1-Distill-Qwen-14B |

Training the 14B model requires a CUDA-capable GPU with sufficient memory. The
fine-tuning commands below are not intended to run on a typical CPU-only host.
![alt text](image-1.png)




## Fine-tuning DeepSeek-R1-Distill-Qwen-14B on our action generation dataset

Command:

```bash
python examples/fine_tune_action_generation.py
```

Expected output:
```text
Fetching 4 files: 100% 4/4 [01:16<00:00, 19.04s/it]
Loading checkpoint shards: 100% 4/4 [00:33<00:00,  8.25s/it]
generation_config.json: 100% 181/181 [00:00<00:00, 2.02MB/s]
README.md: 100% 33.0/33.0 [00:00<00:00, 363kB/s]
action_examples.json: 100% 694M/694M [00:05<00:00, 136MB/s]
Generating train split: 1 examples [00:09,  9.84s/example]
Trainable parameters: 50331648

...

Step: 299, Epoch: 0.1086, Progress: 10.86%, Avg_loss=0.9460, LR=0.00084720, Grad_norm=0.3544, minutes: 315.9855
prediction:
I note that the attacker is actively communicating with our internal and external resources, so I choose to immediately isolate the affected hosts and block all traffic to and from the attacker IPs to stop further spread and data exfiltration.</think>
{
    "Action": "Isolate WikiServer, GitServer, and DevWorkstation; block all traffic to and from 185.140.53.11, 185.140.53.12, and 185.140.53.13 at firewalls and proxies.",
    "Explanation": "Immediate isolation and blocking halt attacker communication and lateral movement."
}
label:
I note that the attacker IPs are actively communicating with internal systems and facilitating lateral movement, so to immediately stop further spread and communication, I choose to block their IPs at the perimeter and isolate the most affected hosts to contain the attack.</think>
{
    "Action": "Block all traffic to attacker IPs 185.140.53.11, 185.140.53.12, and 185.140.53.13 at perimeter firewalls and immediately isolate WikiServer (203.0.113.120) and DevWorkstation (10.66.22.41) from the network.",
    "Explanation": "Cutting external and internal communication halts spread and C2, achieving immediate containment."
}<｜end▁of▁sentence｜>
```


## Fine-tuning DeepSeek-R1-Distill-Qwen-14B on our state prediction dataset

To fine-tune the model for state prediction, use `examples/fine_tune_action_generation.py` and replace its `load_dataset` call with:

```python
load_dataset("kimhammar/CSLE-IncidentResponse-V1", data_files="states_examples.json")
```

Expected output:

```text
Fetching 4 files: 100% 4/4 [01:15<00:00, 18.91s/it]
Loading checkpoint shards: 100% 4/4 [00:34<00:00,  8.63s/it]
generation_config.json: 100% 181/181 [00:00<00:00, 1.36MB/s]
README.md: 100% 33.0/33.0 [00:00<00:00, 242kB/s]
states_examples.json: 100% 1.30G/1.30G [00:04<00:00, 280MB/s]
Generating train split: 1 examples [00:15, 15.77s/ examples]
Trainable parameters: 50331648

Step: 1, Epoch: 0.0006, Progress: 0.06%, Avg_loss=1.7383, LR=0.00095000, Grad_norm=1.3308, minutes: 1.2491

...

Step: 249, Epoch: 0.1594, Progress: 15.93%, Avg_loss=0.4396, LR=0.00079926, Grad_norm=0.1929, minutes: 98.7646
prediction:
I see that reviewing logs and performing forensic triage provides sufficient knowledge to understand the attack timeline and scope, so I update knowledge sufficiency to true.</think>
{
    "are_forensics_preserved": true,
    "is_attack_contained": true,
    "is_eradicated": false,
    "is_hardened": false,
    "is_knowledge_sufficient": true,
    "is_recovered": false
}
label:
By reviewing and analyzing the collected logs and evidence, I gain detailed understanding of the attack timeline and scope. Therefore, knowledge is now sufficient, with forensic evidence preserved and containment maintained.</think>
{
    "are_forensics_preserved": true,
    "is_attack_contained": true,
    "is_eradicated": false,
    "is_hardened": false,
    "is_knowledge_sufficient": true,
    "is_recovered": false
}<｜end▁of▁sentence｜>

...
```


## Fine-tuning DeepSeek-R1-Distill-Qwen-14B on our incident dataset

To fine-tune the model for incident identification, use `examples/fine_tune_action_generation.py` and replace its `load_dataset` call with:

```python
load_dataset("kimhammar/CSLE-IncidentResponse-V1", data_files="incident_examples.json")
```

Expected output:

```text
Fetching 4 files: 100% 4/4 [01:13<00:00, 18.34s/it]
Loading checkpoint shards: 100% 4/4 [00:33<00:00,  8.30s/it]
generation_config.json: 100% 181/181 [00:00<00:00, 1.41MB/s]
README.md: 100% 33.0/33.0 [00:00<00:00, 250kB/s]
incident_examples.json: 100% 190M/190M [00:01<00:00, 135MB/s]
Generating train split: 1 examples [00:02,  2.51s/example]
Trainable parameters: 50331648

Step: 1, Epoch: 0.0016, Progress: 0.16%, Avg_loss=1.1644, LR=0.00095000, Grad_norm=0.4378, minutes: 1.0350

...

Step: 199, Epoch: 0.3184, Progress: 31.84%, Avg_loss=0.6381, LR=0.00064904, Grad_norm=0.1456, minutes: 158.3210
prediction:
I note that in the logs there is no recorded activity or events; the logs are entirely blank, which means there is no evidence of suspicious or malicious behavior to analyze. Given that the system description outlines a peer-to-peer network with a decentralized mesh topology and multiple nodes each performing distinct roles such as bootstrap_node, relay_node, edge_node, validator_node, storage_node, and dht_node, I would expect to see logs indicating routine network traffic, peer discovery, data exchange, or consensus operations if there were any anomalies. The absence of any log entries suggests that the network is operating without issues or alerts. Additionally, the security monitoring system, which is a distributed Snort IDS covering all nodes with logs sent to 172.16.100.5, would normally capture and record any suspicious activities, such as intrusion attempts, known malicious IP connections, or protocol violations. Since no such entries appear in the logs, I infer that no security events or intrusions have been detected. The firewall rules include default allow_p2p_protocols and rate_limit_new_connections, which align with normal p2p network behavior, and the external_restrictions block known malicious IPs and limit new connections, further reducing the chance of successful attacks. Therefore, the combination of an empty log, a secure network design, and active security monitoring strongly supports the conclusion that the system is operating normally and that there is no incident or cyberattack occurring.</think>
{
    "Entities": {},
    "Incident": "No",
    "Incident description": "No incident can be inferred from the logs because they contain no substantial information.",
    "MITRE ATT&CK Tactics": [],
    "MITRE ATT&CK Techniques": []
}
label:
I note that in the logs provided, there is no information or recorded events indicating any abnormal activity, alerts, or warnings that might suggest a cyberattack or incident. Since the logs are completely blank, no suspicious connections, errors, or intrusion detection system (IDS) alerts such as those from Snort are present. I also observe from the system description that the IDS is deployed in a distributed manner covering all nodes, with centralized logging at 172.16.100.5. This comprehensive coverage makes it unlikely that any incidents would go undetected or unlogged if they occurred in the network. Additionally, the network is configured in a secured decentralized mesh topology with clear firewall rules including blocking known malicious IPs and rate-limiting new connections, which further reduces the attack surface and likelihood of successful intrusion. The system’s default policy allows peer-to-peer protocols, which explains normal traffic patterns without triggering alerts. Therefore, considering the absence of any logged suspicious activity, the robust IDS deployment, security firewall policies, and the controlled peer-to-peer environment, I conclude that the current blank logs and system state do not indicate a cyberattack incident but reflect normal operation.</think>
{
    "Entities": {},
    "Incident": "No",
    "Incident description": "No incident can be inferred from the logs because they contain no substantial information.",
    "MITRE ATT&CK Tactics": [],
    "MITRE ATT&CK Techniques": []
}<｜end▁of▁sentence｜>

...
```

## Response generation

Command:

```bash
python examples/response_generation.py
```

Expected output (example):

```text
Loading weights: 100% 579/579 [00:09<00:00, 58.45it/s]
adapter_model.safetensors: 100% 201M/201M [00:14<00:00, 14.2MB/s]
tokenizer_config.json: 100% 3.07k/3.07k [00:00<00:00, 10.3MB/s]
tokenizer.json: 100% 7.03M/7.03M [00:00<00:00, 136MB/s]
README.md: 100% 33.0/33.0 [00:00<00:00, 199kB/s]
examples_16_june.json: 100% 536M/536M [00:08<00:00, 60.4MB/s]
Generating train split: 1 examples [00:09,  9.15s/ examples]
[transformers] Setting `pad_token_id` to `eos_token_id`:151643 for open-end generation.
I understand that simply containing and preserving evidence is not enough; the adversary must be fully removed. Since malicious payloads and backdoors could persist, I choose to perform malware eradication by reimaging affected hosts, applying patches, and removing unauthorized persistence mechanisms.</think>
{
    "Action": "Reimage or malware-scan and clean affected hosts, apply latest patches, and remove any unauthorized persistence mechanisms.",
    "Explanation": "Reimaging and malware removal eradicate malware and close exploited vulnerabilities, ensuring the environment is clean."
}
```


## Author & Maintainer
Yiran Gao gaoyiran525@gmail.com

Kim Hammar <kimham@kth.se>

Tao Li li.tao@cityu.edu.hk
