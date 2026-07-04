# Qwen Recovery Plan Mapping for `llm_ir_dt_new`

This document maps the generated incident-response plan to what this repository can actually execute today, without modifying the existing Python files.

## Scope

The generated plan is a reasonable generic IR workflow, but this repository is a Dockerized research testbed rather than a production recovery platform. As a result, some plan steps can be executed directly, some can only be approximated, and some are currently out of scope.

## Step-by-Step Mapping

### 1. Isolate the attack source

Generated action:

> Isolate the client attack platform (10.0.1.11) by disconnecting it from the network and blocking all inbound and outbound traffic at perimeter firewalls.

Current repository support:

- Partially supported.
- The repository does not currently provide a dedicated "isolate one host" workflow.
- The closest existing operational options are:
  - stop the full digital twin with `stop.py`
  - rebuild and redeploy with `run_recovery.py`

Operational interpretation in this project:

- In this lab, the attack source is the `client` container at `10.0.1.11`.
- If immediate containment is required, the practical response is to stop the environment or proceed directly to recovery.
- Fine-grained client-only isolation would require new orchestration logic or direct Docker commands, which are not implemented in the current Python entrypoints.

Assessment:

- Conceptually valid.
- Not fully automated by the current repository.

### 2. Preserve evidence

Generated action:

> Acquire full disk and memory images of 10.0.1.11, 10.0.2.11, 10.0.2.12, and 10.0.2.13, and export relevant Snort, SSH, and web logs to write-protected storage.

Current repository support:

- Partially supported.
- `run_recovery.py` already exports:
  - deployment status
  - parsed Snort alerts
  - raw Snort alert file
  - selected command outputs from:
    - `client`
    - `server_ssh`
    - `server_samba`
    - `server_shellshock`

What it actually collects:

- Network configuration
- Process listings
- SSH artifacts
- Samba logs
- Apache access/error logs
- File listings and selected file contents

What it does not collect:

- Full disk images
- Memory dumps
- Write-blocked forensic images
- Legally defensible chain-of-custody artifacts

Assessment:

- Log and command-output preservation is supported.
- Full forensic imaging is not supported.

### 3. Perform forensic analysis

Generated action:

> Perform forensic analysis of the collected images and logs to determine the attacker timeline, compromised credentials, and indicators of compromise.

Current repository support:

- Minimally supported.
- The repository exports evidence, but does not perform automated timeline reconstruction or IOC analysis.

What can be inferred manually from current artifacts:

- Attacker origin: `client` / `10.0.1.11`
- Successful credential compromise:
  - SSH: `admin / password123`
- Successful actions:
  - SSH login to `server_ssh`
  - SMB access to `server_samba`
  - Shellshock command execution on `server_shellshock`
- Observable network indicators:
  - ICMP sweep
  - SSH attempts and brute-force alert
  - SMB access
  - HTTP traffic
  - Shellshock signature match

Assessment:

- Manual analysis is possible from exported artifacts.
- Automated forensic analysis is not implemented.

### 4. Eradicate and rebuild

Generated action:

> Rebuild the compromised hosts from trusted images, reset credentials, and remove unauthorized accounts.

Current repository support:

- Partially supported, with one important caveat.
- `run_recovery.py` already:
  - stops the deployed environment
  - rebuilds images
  - redeploys clean containers
  - verifies basic service health

What this effectively achieves in the lab:

- Removes attacker modifications by replacing containers with clean instances.
- Clears transient compromise state.
- Restores the baseline lab topology.

What is not currently implemented:

- Credential rotation as an independent recovery step
- Selective rebuild of only compromised hosts
- Post-incident account review

Important lab-specific caveat:

- Some credentials and vulnerabilities are intentionally reintroduced after rebuild because they are part of the research testbed design.
- For example, weak SSH credentials and vulnerable services exist by design to keep the lab attackable.

Assessment:

- Rebuild-based eradication is supported.
- Secure hardening is not part of the current recovery path.

### 5. Patch and harden

Generated action:

> Patch the vulnerable services, enforce strong authentication, disable SMBv1, and deploy updated IDS signatures.

Current repository support:

- Not supported as part of the current baseline workflow.

Reason:

- The vulnerable services are intentional features of the lab:
  - weak-password SSH server
  - vulnerable Samba image
  - vulnerable Shellshock server

If these were patched, the environment would stop serving its purpose as an attack/recovery research testbed.

Assessment:

- Correct for a real environment.
- In conflict with the design goal of this repository unless a separate "hardened mode" is added.

### 6. Restore services to operation

Generated action:

> Restore the patched services from clean backups, validate functionality, and return the servers to production use.

Current repository support:

- Partially supported in lab form.
- `run_recovery.py` already validates:
  - deployment status
  - ping from client to SSH server
  - HTTP responses from web servers
  - listing of `/home/admin` on the SSH server

What this means in this project:

- Services can be restored to a clean experimental baseline.
- This is not the same as restoring a production environment from enterprise backups.

Assessment:

- Baseline lab restoration is supported.
- Production-grade restoration is out of scope.

## Practical Conclusion

The generated plan can be adapted to this repository as follows:

1. Containment:
   - Stop the lab or proceed immediately to `run_recovery.py`.
2. Evidence preservation:
   - Use `run_recovery.py` to export status, Snort alerts, and host artifacts.
3. Analysis:
   - Review exported JSON and text files under `artifacts/recovery_<timestamp>/`.
4. Eradication:
   - Allow `run_recovery.py` to rebuild images and redeploy clean containers.
5. Validation:
   - Use the built-in verification output from `run_recovery.py`.

This means the answer to "can the system be recovered?" is:

- Yes, in the context of this repository, recovery means exporting evidence and restoring the lab to a clean baseline by rebuilding and redeploying containers.
- No, if recovery is expected to include forensic-grade imaging, selective containment, credential rotation, patching, and hardened production restoration.

## Recommended Wording for This Project

For this repository, a more accurate recovery statement would be:

> The system can be recovered to a clean experimental baseline by exporting available evidence, tearing down the compromised lab, rebuilding the container images, redeploying the digital twin, and validating service availability.

## Commands Already Available

Start the lab:

```powershell
python .\start.py
```

Run the demo commands:

```powershell
python .\run_command.py
```

Run the attack chain:

```powershell
python .\run_attack.py
```

Recover the lab:

```powershell
python .\run_recovery.py
```

Stop the lab:

```powershell
python .\stop.py
```
