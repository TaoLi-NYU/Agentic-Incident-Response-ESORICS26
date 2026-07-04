# LLM IR Digital Twin

Dockerized incident response testbed ("digital twin") for autonomous incident response research. The system emulates a small IT infrastructure with a Snort IDS gateway, a client, and several servers (3 vulnerable + 2 normal).

## Network Topology

```
              CLIENT NETWORK (10.0.1.0/24)
        ┌──────────┐
        │  client   │  10.0.1.11
        └─────┬─────┘
              │
        ┌─────┴──────────────────────────┐
        │  GATEWAY (Snort IDS + Router)   │
        │  eth0: 10.0.1.10 (client_net)  │
        │  eth1: 10.0.2.10 (server_net)  │
        └─────┬──────────────────────────┘
              │
              SERVER NETWORK (10.0.2.0/24)
   ┌──────────┼──────────┬──────────┬──────────┐
   │          │          │          │          │
┌──┴───┐ ┌───┴──┐ ┌─────┴──┐ ┌────┴───┐ ┌───┴────┐
│ssh   │ │samba │ │shell   │ │ web1   │ │ web2   │
│brute │ │cry   │ │shock   │ │nginx+  │ │nginx+  │
│force │ │      │ │        │ │ssh     │ │ssh     │
│.2.11 │ │.2.12 │ │.2.13   │ │.2.14   │ │.2.15   │
└──────┘ └──────┘ └────────┘ └────────┘ └────────┘
```

## IP Address Table

| Host              | Network      | IP Address  |
|-------------------|-------------|-------------|
| Gateway (client)  | client_net  | 10.0.1.10   |
| Gateway (server)  | server_net  | 10.0.2.10   |
| Client            | client_net  | 10.0.1.11   |
| SSH Server        | server_net  | 10.0.2.11   |
| Samba Server      | server_net  | 10.0.2.12   |
| Shellshock Server | server_net  | 10.0.2.13   |
| Web Server 1      | server_net  | 10.0.2.14   |
| Web Server 2      | server_net  | 10.0.2.15   |

## Container Descriptions

| Container         | Services              | Vulnerability               |
|-------------------|-----------------------|-----------------------------|
| `gateway`         | Snort IDS, iptables   | N/A (monitoring)            |
| `client`          | nmap, hydra, curl     | N/A (attack platform)       |
| `server_ssh`      | OpenSSH               | Weak credentials            |
| `server_samba`    | Samba                 | CVE-2017-7494 (SambaCry)    |
| `server_shellshock` | Apache + CGI        | CVE-2014-6271 (Shellshock)  |
| `server_web1`     | Nginx + OpenSSH       | None (normal server)        |
| `server_web2`     | Nginx + OpenSSH       | None (normal server)        |

## Prerequisites

- Docker
- Python 3.11+

## Quick Start

```bash
pip install -e .
docker compose build
```
