"""
Docker management facade for digital-twin deployment.
"""
import logging
import subprocess
from typing import Any, Generator

import docker
from docker.errors import APIError, NotFound

from llm_ir_dt.constants.constants import DOCKER

logger = logging.getLogger(__name__)


class DockerManager:
    """
    Static-method facade for Docker operations on the digital twin.
    """

    @staticmethod
    def _client() -> docker.DockerClient:
        """
        Create a Docker client from the environment.

        :return: a Docker client instance
        """
        return docker.from_env()

    @staticmethod
    def _net_name(net_id: str) -> str:
        """
        Build a Docker network name.

        :param net_id: the network identifier from the config
        :return: the Docker network name
        """
        return f"{DOCKER.NETWORK_PREFIX}{net_id}"

    @staticmethod
    def build_images() -> dict[str, Any]:
        """
        Build all container images using docker compose.

        :return: a dict with build result
        """
        result = subprocess.run(
            ["docker", "compose", "build"],
            capture_output=True,
            text=True,
        )
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    @staticmethod
    def deploy(
        config: dict[str, Any],
    ) -> Generator[dict[str, Any], None, None]:
        """
        Deploy the digital twin on multiple segmented Docker networks.

        Yields progress dicts as each step completes, enabling
        real-time streaming to clients. The final yield is a result
        dict with networks and containers lists.

        :param config: the digital twin configuration with networks/hosts
        :return: a generator of progress/result dicts
        """
        client = DockerManager._client()

        # Create networks
        networks_by_id: dict[str, Any] = {}
        network_names: list[str] = []
        for net_def in config.get("networks", []):
            net_name = DockerManager._net_name(net_def["id"])
            try:
                net_obj = client.networks.get(net_name)
                yield {"type": "progress",
                       "message": f"Using existing network "
                                  f"{net_name}"}
            except NotFound:
                yield {"type": "progress",
                       "message": f"Creating network {net_name}"
                                  f" ({net_def['subnet']})"}
                ipam_pool = docker.types.IPAMPool(
                    subnet=net_def["subnet"],
                    gateway=net_def.get("gateway"),
                )
                ipam_config = docker.types.IPAMConfig(
                    pool_configs=[ipam_pool],
                )
                try:
                    net_obj = client.networks.create(
                        net_name, driver="bridge",
                        ipam=ipam_config,
                    )
                except APIError:
                    # Subnet overlap — find and remove the
                    # conflicting network by matching subnet
                    subnet = net_def["subnet"]
                    yield {
                        "type": "progress",
                        "message":
                            f"Subnet conflict for {subnet}, "
                            f"removing conflicting network...",
                    }
                    for stale in client.networks.list():
                        if stale.name in ("bridge", "host",
                                          "none"):
                            continue
                        attrs = stale.attrs or {}
                        ipam = attrs.get("IPAM", {})
                        for pool in ipam.get("Config", []):
                            if pool.get("Subnet") == subnet:
                                yield {
                                    "type": "progress",
                                    "message":
                                        f"Removing "
                                        f"{stale.name} "
                                        f"(subnet {subnet})",
                                }
                                stale.remove()
                                break
                    net_obj = client.networks.create(
                        net_name, driver="bridge",
                        ipam=ipam_config,
                    )
                yield {"type": "progress",
                       "message": f"Network {net_name} created"}
            networks_by_id[net_def["id"]] = net_obj
            network_names.append(net_name)

        # Create and start containers
        containers: list[dict[str, Any]] = []
        hosts = config.get("hosts", [])
        total = len(hosts)
        for idx, host in enumerate(hosts, 1):
            container_name = f"{DOCKER.CONTAINER_PREFIX}{host['id']}"
            try:
                existing = client.containers.get(container_name)
                yield {
                    "type": "progress",
                    "message":
                        f"[{idx}/{total}] Container "
                        f"{container_name} already exists "
                        f"(status: {existing.status})",
                }
                containers.append({
                    "host_id": host["id"],
                    "container": existing.name,
                    "status": existing.status,
                    "image": host["docker_image"],
                })
                continue
            except NotFound:
                pass

            yield {
                "type": "progress",
                "message": f"[{idx}/{total}] Starting "
                           f"{container_name} "
                           f"({host['docker_image']})",
            }

            create_kwargs: dict[str, Any] = {
                "name": container_name,
                "detach": True,
            }
            if not host.get("use_image_entrypoint", False):
                create_kwargs["command"] = "sleep infinity"
            if host.get("capabilities"):
                create_kwargs["cap_add"] = host["capabilities"]
            if host.get("privileged", False):
                create_kwargs["privileged"] = True
            if host.get("sysctls"):
                create_kwargs["sysctls"] = host["sysctls"]

            container = client.containers.create(
                host["docker_image"], **create_kwargs
            )

            # Connect to each assigned network with its static IP
            ip_addrs = host.get("ip_addresses") or {}
            if isinstance(ip_addrs, dict):
                for net_id, ip_addr in ip_addrs.items():
                    if net_id in networks_by_id:
                        yield {
                            "type": "progress",
                            "message":
                                f"[{idx}/{total}] Connecting "
                                f"{container_name} to {net_id} "
                                f"({ip_addr})",
                        }
                        networks_by_id[net_id].connect(
                            container, ipv4_address=ip_addr,
                        )
            container.start()

            # Disconnect from default bridge to enforce zone
            # segmentation
            try:
                client.networks.get("bridge").disconnect(
                    container
                )
            except Exception:
                pass

            # Delete the default route that Docker adds via
            # the bridge gateway.
            try:
                exec_id = client.api.exec_create(
                    container_name,
                    ["/bin/sh", "-c",
                     "ip route del default 2>/dev/null || true"],
                )["Id"]
                client.api.exec_start(exec_id)
            except Exception:
                pass

            yield {
                "type": "progress",
                "message": f"[{idx}/{total}] Container "
                           f"{container_name} started",
            }
            containers.append({
                "host_id": host["id"],
                "container": container.name,
                "status": container.status,
                "image": host["docker_image"],
            })

        # Apply static routes
        for host in hosts:
            routes = host.get("routes", [])
            if not routes:
                continue
            container_name = f"{DOCKER.CONTAINER_PREFIX}{host['id']}"
            for route in routes:
                cmd = (f"ip route add {route['destination']} "
                       f"via {route['via']}")
                yield {
                    "type": "progress",
                    "message":
                        f"Adding route on {host['id']}: "
                        f"{route['destination']} "
                        f"via {route['via']}",
                }
                try:
                    exec_id = client.api.exec_create(
                        container_name, ["/bin/sh", "-c", cmd],
                    )["Id"]
                    client.api.exec_start(exec_id)
                except Exception:
                    pass

        # Apply post-deploy commands (e.g. iptables rules)
        for host in hosts:
            post_cmds = host.get("post_deploy_commands", [])
            if not post_cmds:
                continue
            container_name = f"{DOCKER.CONTAINER_PREFIX}{host['id']}"
            for cmd in post_cmds:
                yield {
                    "type": "progress",
                    "message":
                        f"Running post-deploy command on "
                        f"{host['id']}: {cmd}",
                }
                try:
                    exec_id = client.api.exec_create(
                        container_name,
                        ["/bin/sh", "-c", cmd],
                    )["Id"]
                    client.api.exec_start(exec_id)
                except Exception:
                    pass

        yield {"type": "progress",
               "message": "Deployment complete"}
        yield {
            "type": "result",
            "data": {
                "networks": network_names,
                "containers": containers,
            },
        }

    @staticmethod
    def stop(
        config: dict[str, Any] | None = None,
    ) -> Generator[dict[str, Any], None, None]:
        """
        Stop and remove digital twin containers and networks.

        When config is provided, only remove that config's containers
        and networks. When None, remove all llm_ir_dt_* resources.

        :param config: optional config dict to scope removal
        :return: a generator of progress/result dicts
        """
        client = DockerManager._client()
        removed: list[str] = []

        if config is not None:
            host_ids = {
                h["id"] for h in config.get("hosts", [])
            }
            container_names: set[str] | None = {
                f"{DOCKER.CONTAINER_PREFIX}{hid}"
                for hid in host_ids
            }
            network_ids = {
                n["id"] for n in config.get("networks", [])
            }
            network_names: set[str] | None = {
                DockerManager._net_name(nid)
                for nid in network_ids
            }
        else:
            container_names = None
            network_names = None

        dt_containers = [
            c for c in client.containers.list(all=True)
            if c.name.startswith(DOCKER.CONTAINER_PREFIX)
            and (container_names is None
                 or c.name in container_names)
        ]
        total = len(dt_containers)
        for idx, container in enumerate(dt_containers, 1):
            yield {
                "type": "progress",
                "message": f"[{idx}/{total}] Removing "
                           f"{container.name}",
            }
            container.remove(force=True)
            removed.append(container.name)
            yield {
                "type": "progress",
                "message": f"[{idx}/{total}] Removed "
                           f"{container.name}",
            }

        for network in client.networks.list():
            if network.name.startswith(DOCKER.NETWORK_PREFIX):
                if (network_names is None
                        or network.name in network_names):
                    yield {
                        "type": "progress",
                        "message": f"Removing network "
                                   f"{network.name}",
                    }
                    network.remove()
                    yield {
                        "type": "progress",
                        "message": f"Network {network.name} "
                                   f"removed",
                    }

        yield {"type": "progress",
               "message": "Shutdown complete"}
        yield {
            "type": "result",
            "data": {"removed": removed},
        }

    @staticmethod
    def status(
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Get the status of digital twin containers and networks.

        When config is provided, only return that config's resources.
        When None, return all llm_ir_dt_* resources.

        :param config: optional config dict to scope status
        :return: a dict with deployed flag, networks list, and containers list
        """
        client = DockerManager._client()

        if config is not None:
            host_ids = {
                h["id"] for h in config.get("hosts", [])
            }
            expected_containers: set[str] | None = {
                f"{DOCKER.CONTAINER_PREFIX}{hid}"
                for hid in host_ids
            }
            expected_networks: set[str] | None = {
                DockerManager._net_name(nid)
                for nid in (
                    n["id"]
                    for n in config.get("networks", [])
                )
            }
        else:
            expected_containers = None
            expected_networks = None

        network_names = [
            n.name for n in client.networks.list()
            if n.name.startswith(DOCKER.NETWORK_PREFIX)
            and (expected_networks is None
                 or n.name in expected_networks)
        ]

        containers = []
        for container in client.containers.list(all=True):
            if container.name.startswith(DOCKER.CONTAINER_PREFIX):
                if (expected_containers is not None
                        and container.name
                        not in expected_containers):
                    continue
                host_id = container.name[
                    len(DOCKER.CONTAINER_PREFIX):
                ]
                try:
                    image_name = (container.image.tags
                                  or ["unknown"])[0]
                except Exception:
                    image_name = "unknown"
                containers.append({
                    "host_id": host_id,
                    "container": container.name,
                    "status": container.status,
                    "image": image_name,
                })

        return {
            "deployed": len(containers) > 0,
            "networks": network_names,
            "containers": containers,
        }

    @staticmethod
    def exec_run(
        container_id: str,
        command: str,
    ) -> dict[str, Any]:
        """
        Execute a shell command on a digital twin container.

        :param container_id: the host id (without prefix)
        :param command: the shell command to execute
        :return: a dict with container, command, exit_code, output
        """
        client = DockerManager._client()
        container_name = f"{DOCKER.CONTAINER_PREFIX}{container_id}"
        container = client.containers.get(container_name)
        exec_id = client.api.exec_create(
            container.id, ["/bin/sh", "-c", command],
            stdout=True, stderr=True,
        )["Id"]
        output = client.api.exec_start(exec_id).decode(
            "utf-8", errors="replace",
        )
        exit_code = client.api.exec_inspect(exec_id)["ExitCode"]
        return {
            "container": container_id,
            "command": command,
            "exit_code": exit_code,
            "output": output,
        }

    @staticmethod
    def read_alerts() -> dict[str, Any]:
        """
        Read Snort alerts from the gateway container.

        Parses the Snort fast-alert format into structured dicts.

        :return: a dict with a list of parsed alerts
        """
        client = DockerManager._client()
        container_name = f"{DOCKER.CONTAINER_PREFIX}gateway"
        container = client.containers.get(container_name)
        exec_id = client.api.exec_create(
            container.id,
            ["/bin/sh", "-c",
             "cat /var/log/snort/alert 2>/dev/null || echo ''"],
            stdout=True, stderr=True,
        )["Id"]
        output = client.api.exec_start(exec_id).decode(
            "utf-8", errors="replace",
        )
        alerts = DockerManager._parse_snort_alerts(output)
        return {"alerts": alerts, "raw": output}

    @staticmethod
    def clear_alerts() -> dict[str, Any]:
        """
        Clear Snort alerts on the gateway container.

        :return: a dict with the result
        """
        client = DockerManager._client()
        container_name = f"{DOCKER.CONTAINER_PREFIX}gateway"
        container = client.containers.get(container_name)
        exec_id = client.api.exec_create(
            container.id,
            ["/bin/sh", "-c",
             "> /var/log/snort/alert"],
            stdout=True, stderr=True,
        )["Id"]
        client.api.exec_start(exec_id)
        exit_code = client.api.exec_inspect(exec_id)["ExitCode"]
        return {
            "cleared": exit_code == 0,
            "exit_code": exit_code,
        }

    @staticmethod
    def _parse_snort_alerts(raw: str) -> list[dict[str, str]]:
        """
        Parse Snort fast-alert output into structured dicts.

        :param raw: the raw alert file content
        :return: a list of parsed alert dicts
        """
        alerts: list[dict[str, str]] = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            alert: dict[str, str] = {"raw": line}
            # Extract timestamp
            if " [**] " in line:
                parts = line.split(" [**] ")
                alert["timestamp"] = parts[0].strip()
                if len(parts) >= 2:
                    alert["message"] = parts[1].strip()
                if len(parts) >= 3:
                    remainder = parts[2].strip()
                    # Extract classification
                    if "[Classification:" in remainder:
                        cls_start = remainder.index(
                            "[Classification:"
                        ) + len("[Classification:")
                        cls_end = remainder.index("]", cls_start)
                        alert["classification"] = remainder[
                            cls_start:cls_end
                        ].strip()
                    # Extract priority
                    if "[Priority:" in remainder:
                        pri_start = remainder.index(
                            "[Priority:"
                        ) + len("[Priority:")
                        pri_end = remainder.index("]", pri_start)
                        alert["priority"] = remainder[
                            pri_start:pri_end
                        ].strip()
                    # Extract protocol and addresses
                    if "} " in remainder:
                        proto_part = remainder.split("} ")
                        proto = proto_part[0].split("{")[-1].strip()
                        alert["protocol"] = proto
                        if len(proto_part) > 1:
                            addr_part = proto_part[1].strip()
                            if " -> " in addr_part:
                                src, dst = addr_part.split(
                                    " -> ", 1
                                )
                                alert["source"] = src.strip()
                                alert["destination"] = dst.strip()
            alerts.append(alert)
        return alerts
