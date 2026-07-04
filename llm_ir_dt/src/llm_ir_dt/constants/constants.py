"""
Constants for the LLM IR Digital Twin project.
"""
from typing import Any


class DOCKER:
    """
    Docker container and network naming constants.
    """

    NETWORK_PREFIX = "llm_ir_dt_net_"
    CONTAINER_PREFIX = "llm_ir_dt_"
    GATEWAY_IMAGE = "llm_ir_dt-gateway:latest"
    CLIENT_IMAGE = "llm_ir_dt-client:latest"
    SSH_IMAGE = "llm_ir_dt-server_ssh:latest"
    SAMBA_IMAGE = "llm_ir_dt-server_samba:latest"
    SHELLSHOCK_IMAGE = "llm_ir_dt-server_shellshock:latest"
    WEB_IMAGE = "llm_ir_dt-server_web:latest"


class DIGITAL_TWIN:
    """
    Default digital twin topology configuration.
    """

    DEFAULT_CONFIG: dict[str, Any] = {
        "networks": [
            {
                "id": "client_net",
                "name": "Client Network",
                "subnet": "10.0.1.0/24",
                "gateway": "10.0.1.1",
            },
            {
                "id": "server_net",
                "name": "Server Network",
                "subnet": "10.0.2.0/24",
                "gateway": "10.0.2.1",
            },
        ],
        "hosts": [
            {
                "id": "gateway",
                "docker_image": "llm_ir_dt-gateway:latest",
                "use_image_entrypoint": True,
                "capabilities": ["NET_ADMIN", "NET_RAW"],
                "sysctls": {"net.ipv4.ip_forward": "1"},
                "ip_addresses": {
                    "client_net": "10.0.1.10",
                    "server_net": "10.0.2.10",
                },
                "routes": [],
                "post_deploy_commands": [
                    "iptables -P FORWARD ACCEPT",
                    "iptables -t nat -A POSTROUTING -j MASQUERADE",
                ],
            },
            {
                "id": "client",
                "docker_image": "llm_ir_dt-client:latest",
                "use_image_entrypoint": True,
                "capabilities": ["NET_ADMIN", "NET_RAW"],
                "ip_addresses": {
                    "client_net": "10.0.1.11",
                },
                "routes": [
                    {
                        "destination": "10.0.2.0/24",
                        "via": "10.0.1.10",
                    },
                ],
                "post_deploy_commands": [],
            },
            {
                "id": "server_ssh",
                "docker_image": "llm_ir_dt-server_ssh:latest",
                "use_image_entrypoint": True,
                "capabilities": ["NET_ADMIN"],
                "ip_addresses": {
                    "server_net": "10.0.2.11",
                },
                "routes": [
                    {
                        "destination": "10.0.1.0/24",
                        "via": "10.0.2.10",
                    },
                ],
                "post_deploy_commands": [],
            },
            {
                "id": "server_samba",
                "docker_image": "llm_ir_dt-server_samba:latest",
                "use_image_entrypoint": True,
                "capabilities": ["NET_ADMIN"],
                "ip_addresses": {
                    "server_net": "10.0.2.12",
                },
                "routes": [
                    {
                        "destination": "10.0.1.0/24",
                        "via": "10.0.2.10",
                    },
                ],
                "post_deploy_commands": [],
            },
            {
                "id": "server_shellshock",
                "docker_image": "llm_ir_dt-server_shellshock:latest",
                "use_image_entrypoint": True,
                "capabilities": ["NET_ADMIN"],
                "ip_addresses": {
                    "server_net": "10.0.2.13",
                },
                "routes": [
                    {
                        "destination": "10.0.1.0/24",
                        "via": "10.0.2.10",
                    },
                ],
                "post_deploy_commands": [],
            },
            {
                "id": "server_web1",
                "docker_image": "llm_ir_dt-server_web:latest",
                "use_image_entrypoint": True,
                "capabilities": ["NET_ADMIN"],
                "ip_addresses": {
                    "server_net": "10.0.2.14",
                },
                "routes": [
                    {
                        "destination": "10.0.1.0/24",
                        "via": "10.0.2.10",
                    },
                ],
                "post_deploy_commands": [],
            },
            {
                "id": "server_web2",
                "docker_image": "llm_ir_dt-server_web:latest",
                "use_image_entrypoint": True,
                "capabilities": ["NET_ADMIN"],
                "ip_addresses": {
                    "server_net": "10.0.2.15",
                },
                "routes": [
                    {
                        "destination": "10.0.1.0/24",
                        "via": "10.0.2.10",
                    },
                ],
                "post_deploy_commands": [],
            },
        ],
    }
