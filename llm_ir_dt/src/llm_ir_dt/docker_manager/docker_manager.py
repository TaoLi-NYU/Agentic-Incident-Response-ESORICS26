"""
真正负责“创建网络、创建容器、接多张网卡、分配静态 IP、加路由、跑 Snort、执行命令、读告警、最后清理”的
  - 创建容器                                                                                                                                             
  - 接到两个 Docker 网络                                                                                                                                 
  - 启动容器                                                                                                                                             
  - 尝试移除默认 bridge 网络                                                                                                                             
  - 给其他主机加静态路由                                                                                                                                 
  - 最后在 gateway 里执行 post_deploy_commands 里设置 iptables 规则，禁止两个网络直接通信，必须经过 gateway 转发。
  - 之后 main.py 里会执行一些测试命令，监听 Snort 报警，并最终停止并清理容器和网络。
  - 这个文件的核心是 deploy() 方法，接收 config，创建网络和容器，连接网络，执行命令，并通过 yield 实时返回进度和结果。

它的上游是 main.py，下游是 Docker 引擎和各个容器
main.py 只是按顺序调用它：
  1. build_images()
  2. deploy(config)
  3. status()
  4. exec_run(...)
  5. read_alerts()
  6. stop()"""

"""
Docker management facade for digital-twin deployment.
"""
import logging
import subprocess
from typing import Any, Generator

import docker
from docker.errors import NotFound

from llm_ir_dt.constants.constants import DOCKER

logger = logging.getLogger(__name__)


class DockerManager:
    """
    Static-method facade for Docker operations on the digital twin.
    """

    @staticmethod
    def _client() -> docker.DockerClient:
        """
        - 从当前环境创建一个 Docker 客户端                                                                                                                     
        - Python 后续所有网络、容器、exec 操作都靠它 
        Create a Docker client from the environment.

        :return: a Docker client instance
        """
        return docker.from_env()

    @staticmethod
    def _exec_shell(
        client: docker.DockerClient,
        container_name: str,
        command: str,
    ) -> tuple[str, int]:
        """
        Execute a shell command in a container and return output/exit code.
        """
        exec_id = client.api.exec_create(
            container_name,
            ["/bin/sh", "-c", command],
            stdout=True,
            stderr=True,
        )["Id"]
        output = client.api.exec_start(exec_id).decode(
            "utf-8", errors="replace",
        )
        exit_code = client.api.exec_inspect(exec_id)["ExitCode"]
        return output, exit_code

    @staticmethod
    def _gateway_interfaces(
        client: docker.DockerClient,
        container_name: str,
    ) -> list[str]:
        """
        Return non-loopback interfaces for the gateway container.
        """
        output, exit_code = DockerManager._exec_shell(
            client, container_name, "ls /sys/class/net",
        )
        if exit_code != 0:
            return []
        return [
            iface for iface in (
                line.strip() for line in output.splitlines()
            )
            if iface and iface != "lo"
        ]

    @staticmethod
    #  如果传入 client_net，输出就是：                                                                                                                        
    #  llm_ir_dt_net_client_net
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
        docker compose = 用一个配置文件，一键启动一整套容器系统
        Build all container images using docker compose.

        :return: a dict with build result
        """
        result = subprocess.run(
            ["docker", "compose", "build"],
            capture_output=True,
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        stderr = result.stderr.decode("utf-8", errors="replace")
        # 相当于在终端输入 docker compose build 
        # 根据 docker-compose.yml，自动构建所有镜像，负责镜像构建来源和镜像名
        # docker_manager.py 负责实验网络和容器编排
        return {
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
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

        """Create networks"""

        # 然后逻辑是：- 如果这个网络已经存在，就复用 - 如果不存在，就创建
        # 创建时最关键的是用了 IPAM(IP address management)：
        # - subnet=10.0.1.0/24 / 10.0.2.0/24 - gateway=10.0.1.1 / 10.0.2.1
        # IP 子网划分（subnetting）+虚拟交换机（Docker bridge） 子网 = 一组 IP 地址范围  同一个 subnet 内 → 可以直接通信（不需要 router）
        # 所以这里不是让 Docker 自动分配地址，而是把网段规则固定死了，后续容器连接时也会分配固定 IP，保证网络拓扑稳定可预测。
        networks_by_id: dict[str, Any] = {}
        network_names: list[str] = []
        #遍历constants.py里，得到 client_net 和 server_net 的定义
        for net_def in config.get("networks", []):  
            # 每个网络会先通过 _net_name() 转成真正的 Docker 网络名，比如：- client_net -> llm_ir_dt_net_client_net
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
                # Docker 默认会：自动生成 subnet（随机）自动分配 IP（随机）比如：172.18.0.0/16
                # 这里用IPAM是为了可控实验环境（digital twin）
                
                ipam_pool = docker.types.IPAMPool(
                    subnet=net_def["subnet"],
                    gateway=net_def.get("gateway"),
                )
                ipam_config = docker.types.IPAMConfig(
                    pool_configs=[ipam_pool],
                )
                # Docker bridge 是一个基于 Linux 内核的虚拟二层交换网络，用于在同一子网内连接多个容器并实现直接通信，同时与其他网络隔离
                # bridge = 同一网段的“局域网”  router = 不同网段之间的“中转站”
                # client_net（一个 bridge） server_net（另一个 bridge）
                net_obj = client.networks.create(
                    net_name, driver="bridge",
                    ipam=ipam_config,
                )
                yield {"type": "progress",
                       "message": f"Network {net_name} created"}
            networks_by_id[net_def["id"]] = net_obj
            network_names.append(net_name)

        """ Create and start containers"""

        """
        docker:管理容器（创建、启动、网络、隔离）
        container:容器是一个轻量级、可移植的运行环境，包含应用程序及其依赖项。Docker 通过容器技术实现资源隔离和高效利用。
        这部分代码的核心逻辑是： 
        “先根据 host 配置准备出一个干净的容器壳子。”                                                                                                           
                                                                                                                                                         
        用 client 举个具体例子。配置里 client 大概是：                                                                                                         
                                                                                                                                                                
        - id = "client"                                                                                                                                        
        - docker_image = "llm_ir_dt-client:latest"                                                                                                             
        - capabilities = ["NET_ADMIN", "NET_RAW"]                                                                                                              
        - use_image_entrypoint = True                                                                                                                          
                                                                                                                                                                
        那么这里实际效果接近于：                                                                                                                               

            detach=True,
            cap_add=["NET_ADMIN", "NET_RAW"]
        )

        这时只是把 llm_ir_dt_client 创建出来；真正接入 client_net、分配 10.0.1.11、再加去 10.0.2.0/24 的路由，是后面那几段代码完成的
        
        在 client 容器里加入一条静态路由，告诉它：
        如果你要访问 10.0.2.0/24 这个网段，不要自己瞎走，下一跳要发给 10.0.1.10

        1. client 发现目标 10.0.2.11 不在自己本地网段 10.0.1.0/24                                                                                              
        2. 查路由表，匹配到 10.0.2.0/24 via 10.0.1.10                                                                                                          
        3. 所以它把数据包先发给 gateway                                                                                                                        
        4. gateway 再把包转发到 server_net                                                                                                                     
        5. server_ssh 收到包后，回包时也有反向静态路由，经 10.0.2.10 回到 client
        """
        
        # 遍历 hosts 创建容器
        containers: list[dict[str, Any]] = []
        hosts = config.get("hosts", [])
        total = len(hosts)
        # 容器名统一加前缀，比如: - gateway -> llm_ir_dt_gateway - client -> llm_ir_dt_client
        for idx, host in enumerate(hosts, 1):
            container_name = f"{DOCKER.CONTAINER_PREFIX}{host['id']}"
            # 意思是：先去 Docker 里查一下，这个名字的容器是不是已经存在。reload() 是刷新状态，确保 existing.status 是最新的
            try:
                existing = client.containers.get(container_name)
                existing.reload()
                # 容器存在且状态是 running：直接复用，跳过创建
                if existing.status == "running":
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
                # 第二种，容器存在但没在运行：先删除它，后续会重新创建一个新的同名容器
                yield {
                    "type": "progress",
                    "message":
                        f"[{idx}/{total}] Container "
                        f"{container_name} exists but is "
                        f"{existing.status}; recreating",
                }
                existing.remove(force=True)
            # 第三种，
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
            #   这表示：如果不想用 Docker 镜像里原本定义的 ENTRYPOINT，就强行让容器执行 sleep infinity. 
            #   效果是容器会一直挂着，但不主动跑服务。这个模式常用于“先把容器拉起来，后面再用 docker exec 注入命令”
            if not host.get("use_image_entrypoint", False):
                create_kwargs["command"] = "sleep infinity" # 用容器当“虚拟主机”, 你需要容器一直在线，随时执行命令
            # 从 host 配置里取 "capabilities" 把 capabilities 加到 Docker 创建容器的参数里
            # capabilities 是 Linux 容器的一个安全特性，允许容器获得一些额外的权限。比如 NET_ADMIN 让容器能管理网络，NET_RAW 让容器能使用原始套接字（比如运行 Snort 需要）。这个配置项让用户可以灵活地给不同的容器分配不同的权限。
            if host.get("capabilities"):
                create_kwargs["cap_add"] = host["capabilities"]
            # 如果配置要求，就让容器以更高权限运行。这个项目默认主要靠 capability，不一定每台都开 privileged
            if host.get("privileged", False):
                create_kwargs["privileged"] = True
            # 给容器设置内核参数                                                                                                                                 
            # 最典型的是 gateway 配了： "net.ipv4.ip_forward": "1"  这样它才能做三层转发，扮演路由器
            # 默认（ip_forward = 0）一台机器只处理“发给自己”的数据包，不能转发给其他机器。开启 ip_forward 后，这台机器就能把收到的包转发给其他机器，充当路由器的角色。
            if host.get("sysctls"):
                create_kwargs["sysctls"] = host["sysctls"]
            # 这一步只是“创建”，还没启动容器。后续会调用 container.start() 来真正启动它。
            container = client.containers.create(
                host["docker_image"], **create_kwargs
            )

            """ Connect to each assigned network with its static IP"""

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
                        # 拿client举例，llm_ir_dt_client 就会被接入 llm_ir_dt_net_client_net，并且在这个网段里拿到固定地址 10.0.1.11
                        networks_by_id[net_id].connect(
                            container, ipv4_address=ip_addr,
                        )
            # start() 才是真正启动容器。前面的 client.containers.create(...) 只是创建了一个“还没运行”的容器对象。
            # reload() 是从 Docker 重新拉一遍最新状态，避免本地对象里的 status 还是旧值
            container.start()
            container.reload()

            # Disconnect from default bridge to enforce zone
            # segmentation
            # 是在尝试把容器从 Docker 默认的 bridge 网络断开。因为 Docker 创建容器时通常会先自动挂到默认桥接网络上，           
            # 但你的实验拓扑希望容器只存在于你定义的client_net / server_net 这些分区网络里，这样隔离更干净
            try:
                client.networks.get("bridge").disconnect(
                    container
                )
            except Exception:
                pass

            # Delete the default route that Docker adds via
            # the bridge gateway.
            # 走默认路由 → 10.0.1.1（Docker bridge） 结果：绕过你的 gateway（10.0.1.10），不是想要的结果 
            # 2>/dev/null 是为了 suppress 错误输出，因为有些容器可能没有默认路由，删除时会报错，但这不影响后续步骤，所以直接忽略错误。
            try:
                exec_id = client.api.exec_create(
                    container_name,
                    ["/bin/sh", "-c",
                     "ip route del default 2>/dev/null || true"], 
                )["Id"]
                client.api.exec_start(exec_id)
                exit_code = client.api.exec_inspect(exec_id)[
                    "ExitCode"
                ]
                # 这个命令执行的“返回码” exit_code 是 Linux 命令的退出状态码，0 表示成功，非0表示失败。比如如果容器里没有默认路由，这条命令就会失败，返回非0，但这不影响后续步骤，所以只是记录一下日志，不做其他处理。
                if exit_code != 0:
                    yield {
                        "type": "progress",
                        "message":
                            f"[{idx}/{total}] Failed to delete "
                            f"default route on {container_name} "
                            f"(exit_code={exit_code})",
                    }
            except Exception:
                pass
            # 输出如下： 2026-04-06 00:19:23,656 [    INFO] Deploy: {'type': 'progress', 'message': '[1/7] Container llm_ir_dt_gateway started'} (main.py:39)
            yield {
                "type": "progress",
                "message": f"[{idx}/{total}] Container "
                           f"{container_name} started",
            }
            # 是把这个已经处理过的容器记录到结果里，后面 deploy() 结束时会统一返回给调用方
            containers.append({
                "host_id": host["id"],
                "container": container.name,
                "status": container.status,
                "image": host["docker_image"],
            })

        # Apply static routes
        # 前面容器已经被创建、接入指定 Docker 网络、分配了固定 IP，也已经尽量删除了 Docker 自动加的默认路由。到这里，容器虽然“在线”，但未必知道  怎么去另一个子网，所以这里要手动补路由
        for host in hosts:
            routes = host.get("routes", [])
            if not routes:
                continue
            #  把逻辑主机名转成真实 Docker 容器名。比如：- client -> llm_ir_dt_client
            container_name = f"{DOCKER.CONTAINER_PREFIX}{host['id']}"
            for route in routes:
                # cmd只是一个字符串（string）
                cmd = (f"ip route replace {route['destination']} "
                       f"via {route['via']}")
                # [    INFO] Deploy: {'type': 'progress', 'message': 'Adding route on client: 10.0.2.0/24 via 10.0.1.10'} (main.py:39)
                yield {
                    "type": "progress",
                    "message":
                        f"Adding route on {host['id']}: "
                        f"{route['destination']} "
                        f"via {route['via']}",
                }
                # cmd（字符串） ->  传给 /bin/sh -c  ->  在容器里执行
                #  这里不是在宿主机执行，而是相当于：docker exec llm_ir_dt_client /bin/sh -c "ip route replace ..." 
                #  也就是进入目标容器内部执行这条 ip route 命令
                try:
                    # 在容器 namespace 里创建一个新的进程（但还没启动）
                    # 你不是直接运行命令，而是创建一个“执行对象” , exec_id 就像：任务编号 / 句柄（handle）
                    exec_id = client.api.exec_create(
                        container_name, ["/bin/sh", "-c", cmd],
                    )["Id"]
                    client.api.exec_start(exec_id)
                    exit_code = client.api.exec_inspect(exec_id)[
                        "ExitCode"
                    ]
                    # 随后检查退出码： 如果退出码不是 0，说明命令失败，会继续 yield 一个失败提示。
                    if exit_code != 0:
                        yield {
                            "type": "progress",
                            "message":
                                f"Route command failed on "
                                f"{host['id']} (exit_code="
                                f"{exit_code}): {cmd}",
                        }
                except Exception:
                    pass

        # Apply post-deploy commands (e.g. iptables rules)
        # 这段是在“容器和路由都准备好之后”，执行每台主机额外的初始化命令。你可以把它理解成部署流程的最后收尾阶段
        #gateway 容器里继续执行三件事：                                                                                              
                                                                                                                                                         
        #1. 开启转发策略，允许 FORWARD                                                                                                                          
        #2. 配置 NAT/MASQUERADE                                                                                                                                 
        #3. 启动 Snort 监控   

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
                    _, exit_code = DockerManager._exec_shell(
                        client, container_name, cmd,
                    )
                    if exit_code != 0:
                        yield {
                            "type": "progress",
                            "message":
                                f"Post-deploy command failed on "
                                f"{host['id']} (exit_code="
                                f"{exit_code}): {cmd}",
                        }
                except Exception:
                    pass

        gateway_name = f"{DOCKER.CONTAINER_PREFIX}gateway"
        gateway_ifaces = DockerManager._gateway_interfaces(
            client, gateway_name,
        )
        if gateway_ifaces:
            yield {
                "type": "progress",
                "message":
                    "Detected gateway interfaces for Snort: "
                    f"{', '.join(gateway_ifaces)}",
            }
        else:
            yield {
                "type": "progress",
                "message":
                    "No non-loopback gateway interfaces detected for Snort",
            }

        for iface in gateway_ifaces:
            cmd = (
                "snort -c /etc/snort/snort.conf "
                f"-i {iface} -l /var/log/snort/ -A fast -D"
            )
            yield {
                "type": "progress",
                "message":
                    f"Starting Snort on gateway interface {iface}",
            }
            try:
                _, exit_code = DockerManager._exec_shell(
                    client, gateway_name, cmd,
                )
                if exit_code != 0:
                    yield {
                        "type": "progress",
                        "message":
                            f"Snort failed on interface {iface} "
                            f"(exit_code={exit_code})",
                    }
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
        # 它和 deploy() 一样，也是个 generator，所以不会一次性返回，而是边删边 yield 进度信息
        """
        - 传 config                                                                                                                                            
        只删除这份配置里定义的容器和网络                                                                                                                     
         
        - 不传                                                                                                                                                 
        删除所有名字前缀符合 llm_ir_dt_* 的资源
        """
        
        
        """
        Stop and remove digital twin containers and networks.

        When config is provided, only remove that config's containers
        and networks. When None, remove all llm_ir_dt_* resources.

        :param config: optional config dict to scope removal
        :return: a generator of progress/result dicts
        """

        # 这里先拿 Docker client，然后准备一个 removed 列表，用来记录删掉了哪些容器
        client = DockerManager._client()
        removed: list[str] = []

        #   如果传了配置，就先提取所有 host 的逻辑 ID
        if config is not None:
            host_ids = {
                h["id"] for h in config.get("hosts", [])
            }
            container_names: set[str] | None = {
                f"{DOCKER.CONTAINER_PREFIX}{hid}"
                for hid in host_ids
            }
            #   - client_net - server_net
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

        """
        1. 容器名必须以 llm_ir_dt_ 开头                                                                                                                        
        防止误删不属于本项目的容器                                                                                                                          
        2. 如果传了 config，还必须在那份配置的目标名单里                                                                                                       
        进一步缩小范围  
        """
        dt_containers = [
            c for c in client.containers.list(all=True) # all=True 表示不只是运行中的容器，连已停止的也会列出来。这样清理更彻底
            if c.name.startswith(DOCKER.CONTAINER_PREFIX)
            and (container_names is None
                 or c.name in container_names)
        ]
        total = len(dt_containers)

        #   为什么是“先删容器，再删网络”？ 因为 Docker 不允许删除仍有容器连接着的网络
        for idx, container in enumerate(dt_containers, 1):
            yield {
                "type": "progress",
                "message": f"[{idx}/{total}] Removing "
                           f"{container.name}",
            }
            container.remove(force=True) # force=True 表示即使容器正在运行也强制删除，这样就不需要先 stop 再 remove 了
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


    """
    - deploy() 创建环境
    - status() 查看环境
    - stop() 销毁环境
    """
    
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
        #  - 这个 digital twin 现在有没有部署出来？ - 有哪些网络？- 有哪些容器？- 它们是什么状态、用的什么镜像？   
        # 获取 Docker 客户端
        client = DockerManager._client()
        # 这里先从配置里取出所有主机 ID，比如：{"gateway", "client", "server_ssh", ...} 
        if config is not None:
            host_ids = {
                h["id"] for h in config.get("hosts", [])
            }
            # 接着拼出这些主机在 Docker 里的真实容器名："llm_ir_dt_gateway", "llm_ir_dt_client"...
            expected_containers: set[str] | None = {
                f"{DOCKER.CONTAINER_PREFIX}{hid}"
                for hid in host_ids
            }
            # 然后同理，生成配置里应该存在的网络名：client_net 会被 _net_name() 转成：llm_ir_dt_net_client_net
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
        # 3. 查网络 - 列出所有 Docker 网络，过滤出名字符合 llm_ir_dt_net_* 前缀的，并且如果传了 config 就进一步筛选只保留配置里定义的网络
        network_names = [
            n.name for n in client.networks.list()
            if n.name.startswith(DOCKER.NETWORK_PREFIX)
            and (expected_networks is None
                 or n.name in expected_networks)
        ]
        # 4. 查容器 - 列出所有 Docker 容器，过滤出名字符合 llm_ir_dt_* 前缀的，并且如果传了 config 就进一步筛选只保留配置里定义的容器。对于每个符合条件的容器，记录它的 host_id（从容器名解析出来的逻辑主机 ID）、状态、使用的镜像等信息，最后返回一个包含部署状态、网络列表和容器列表的结果。
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
        """
        1. 找到目标容器
        2. 在容器里创建一次 shell 执行任务
        3. 启动执行并读取输出
        4. 返回退出码和输出文本
        
        exec_create	 定义任务
        exec_start	 执行
        exec_inspect 查询
        """
        client = DockerManager._client()
        container_name = f"{DOCKER.CONTAINER_PREFIX}{container_id}"
        container = client.containers.get(container_name)
        # 它不是新建容器，而是在“已经运行的容器内部”创建一次 exec 任务
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
        # read_alerts() 的作用是：到 gateway 容器里把 Snort 产生的告警日志读出来，再解析成结构化数据返回
        # 先拿 Docker 客户端
        client = DockerManager._client()
        container_name = f"{DOCKER.CONTAINER_PREFIX}gateway"
        container = client.containers.get(container_name)
        """
          它在 gateway 容器里执行一条 shell 命令： cat /var/log/snort/alert 2>/dev/null || echo ''                                                                                                        
                                                                                                                                                         
          这条命令的意思是：                                                                                                                           
          - cat /var/log/snort/alert                                                                                                                             
          读取 Snort 告警文件内容                                                                                                                              
          - 2>/dev/null                                                                                                                                          
          把错误输出丢掉，不显示“文件不存在”等报错                                                                                                             
        - || echo ''                                                                                                                                           
         如果 cat 失败，就输出一个空字符串                                                                                                                    
                                                                                                                                                         
        所以这个设计的目的很明确：即使告警文件还没生成，也不要让函数直接报错，而是平稳返回空内容
        """
        
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
        """
        - 文件还在
        - 内容被清空
        - 相当于把历史告警全部擦掉
        """
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
        
        """
        - raw.strip() 去掉整个文本前后的空白                                                                                                                   
        - .split("\n") 按行拆分                                                                                                                                
        - 每一行再 strip()                                                                                                                                     
        - 空行直接跳过
        """
        alerts: list[dict[str, str]] = []
        for line in raw.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            # 无论后面能不能成功解析，先把原始整行保留下来。至少不会丢失原始告警内容
            alert: dict[str, str] = {"raw": line}
            """
            Snort fast-alert 常见格式里，[**] 是一个明显分隔符，所以这里用它切分。                                                                                                                                               
            通常一条告警大概像这样：                                                                                                                                      
            04/08-12:34:56.789012  [**] [1:1000001:0] Test alert [**] [Classification: Attempted Admin Privilege Gain] [Priority: 1] {TCP} 10.0.1.11:12345 ->      
            10.0.2.11:22                                                                                                                                      
             用 " [**] " 分割后，大概会得到：                                                                                                                               
            - parts[0] = 时间戳                                                                                                                                    
            - parts[1] = 告警消息部分                                                                                                                              
            - parts[2] = 后面的分类、优先级、协议、地址信息
            
            [                                                                                                                                                      
                {                                                                                                                                                  
                    "raw": "04/08-12:34:56.789012  [**] [1:1000001:0] Test alert [**] [Classification: Attempted Admin Privilege Gain] [Priority: 1] {TCP}         
            10.0.1.11:12345 -> 10.0.2.11:22",                                                                                                                      
                    "timestamp": "04/08-12:34:56.789012",                                                                                                          
                    "message": "[1:1000001:0] Test alert",                                                                                                         
                    "classification": "Attempted Admin Privilege Gain",                                                                                            
                    "priority": "1",                                                                                                                               
                    "protocol": "TCP",                                                                                                                             
                    "source": "10.0.1.11:12345",                                                                                                                   
                    "destination": "10.0.2.11:22",                                                                                                                 
                }                                                                                                                                                  
            ] 
            
            """ 

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
