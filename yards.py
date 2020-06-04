#!/usr/bin/env python3

import dataclasses
import json
import signal
import shlex
import sys
from subprocess import PIPE, STDOUT, CalledProcessError, check_output, run
from tempfile import NamedTemporaryFile
from time import sleep, time
from typing import Dict, List, Optional
from pathlib import Path


"""
yards tries to keep containers described in the config alive and running with the correct settings.

When doing so it writes result of those efforts into status file.

It is designed to run as a container itself with docker.sock accessible as a volume.
Or it can run in a cron.
"""


@dataclasses.dataclass
class Container:
    id: Optional[str]
    name: str
    image: str
    ports: List[str]
    env: Dict[str, str]
    command: str
    volumes: List[str]
    log_driver: str
    log_options: Dict[str, str]
    running: bool
    restarts: int = 0


@dataclasses.dataclass
class Config:
    wait_seconds: int
    daemon: bool
    ignore_labels: List[str]
    ignore_images: List[str]
    containers: Dict[str, Container]


@dataclasses.dataclass
class ContainerStatus:
    latest_running: bool
    latest_start_error: str = ""
    previous_restored: bool = False
    previous_restore_error: str = ""


@dataclasses.dataclass
class Status:
    container_statuses: Dict[str, ContainerStatus]
    last_update_time: int


def build_env_dict_from_inspect(docker_env: List[str]) -> Dict[str, str]:
    """
    Converts docker's format of Env into dict.

    [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ]

    Turns into:

    {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    }
    """
    env = {}
    for line in docker_env:
        split = line.split("=", 1)
        env[split[0]] = split[1] if len(split) > 1 else ""

    return env


def build_ports_list_from_inspect(docker_ports: Dict[str, List[Dict[str, str]]]) -> List[str]:
    """
    Takes Docker's format of PortBindings from inspect and returns list of strings:

    {
        "9001/tcp": [
            {
                "HostIp": "0.0.0.0",
                "HostPort": "10001"
            },
            {
                "HostIp": "101.101.101.102",
                "HostPort": "10001"
            }
        ]
    }

    Turns into:
    ["10001:9001/tcp", "101.101.101.102:10001:9001/tcp"]

    Drops 0.0.0.0 ip if it is present.

    """
    ports = []
    for container_port, port_configs in docker_ports.items():
        if not port_configs:
            continue
        for port_config in port_configs:
            if port_config["HostIp"] == "0.0.0.0":
                ports.append(f"{port_config['HostPort']}:{container_port}")
            else:
                ports.append(f"{port_config['HostIp']}:{port_config['HostPort']}:{container_port}")

    return ports


def inspect_container(name_or_id: str, ignore_labels: List[str], ignore_images: List[str]) -> Optional[Container]:
    """
    Will run docker inspect for container by name and return results of inspection.
    If can't find container will return None.
    Also will return None for containers which should be ignored (like yards itself and ignored labels & images).
    """

    inspect = json.loads(check_output(["docker", "inspect", name_or_id]))

    if inspect:
        inspect = inspect[0]

    config = inspect.get("Config", {}) or {}
    name = inspect.get("Name", "")
    container_id = inspect.get("Id", "")

    labels = config.get("Labels", {}) or {}
    labels_set = set(label.lower() for label in labels.keys())
    # Will ignore with labels
    if labels_set.intersection(ignore_labels):
        print(f"Ignoring {name}/{container_id} because of labels {labels_set}")
        return None
    image = config.get("Image", "")
    # Will ignore itself
    if "metaso/yards" in image:
        print(f"Ignoring {name}/{container_id} because it is me")
        return None
    # Will ignore images
    if list(i for i in ignore_images if i in image):
        print(f"Ignoring {name}/{container_id} because of the image {image}")
        return None
    host_config = inspect.get("HostConfig", {}) or {}
    network_settings = inspect.get("NetworkSettings", {}) or {}
    docker_ports = network_settings.get("Ports", {}) or {}
    docker_env = config.get("Env", []) or []

    if name and container_id:
        return Container(
            id=container_id,
            name=name,
            image=image,
            ports=build_ports_list_from_inspect(docker_ports=docker_ports),
            env=build_env_dict_from_inspect(docker_env=docker_env),
            command=" ".join(config.get("Cmd", []) or []),
            volumes=host_config.get("Binds", []) or [],  # type: ignore
            log_driver=host_config.get("LogConfig", {}).get("Type", "") or "",
            log_options=host_config.get("LogConfig", {}).get("Config", {}) or {},
            running=inspect.get("State", {}).get("Running", False) or False,
        )
    return None


def read_existing_containers(ignore_labels: List[str], ignore_images: List[str]) -> Dict[str, Container]:
    """
    Will find what is currently running and with what parameters.
    """
    containers = {}

    # Will get just list of IDs and then inspect each
    all_ids = check_output(["docker", "ps", "--all", "--format", "{{.ID}}", "--no-trunc"], text=True).split()
    for running_id in all_ids:
        container = inspect_container(running_id, ignore_labels=ignore_labels, ignore_images=ignore_images)
        if container:
            containers[container.name] = container
    return containers


def parse_config(raw_config: Dict) -> Config:
    containers = {}
    for name, raw_container in raw_config.get("containers", {}).items():
        # name in docker starts with slash
        if not name.startswith("/"):
            name = f"/{name}"
        # ports should really end with protocol
        ports = []
        for port_string in raw_container.get("ports", []):
            if "/" in port_string:
                ports.append(port_string)
            else:
                ports.append(f"{port_string}/tcp")

        containers[name] = Container(
            id=None,
            name=name,
            image=raw_container.get("image", ""),
            ports=ports,
            env=raw_container.get("env", {}),
            command=raw_container.get("command", {}),
            volumes=raw_container.get("volumes", []),
            log_driver=raw_container.get("log_driver", "") or "json-file",
            log_options=raw_container.get("log_options", ""),
            running=True,
        )
    return Config(
        wait_seconds=raw_config.get("wait_seconds", 0),
        daemon=raw_config.get("daemon", False),
        ignore_labels=list(l.lower() for l in raw_config.get("ignore_labels", [])),
        ignore_images=list(l.lower() for l in raw_config.get("ignore_images", [])),
        containers=containers,
    )


def remove_container(name: str):
    run(["docker", "stop", "--time", "20", name])
    run(["docker", "rm", name])


def start_container_return_error(container: Container) -> Optional[str]:
    """
    Will try to start a container.
    If it starts returns None, if it fails - returns error.
    """
    optional = []
    for ports_string in container.ports:
        optional.extend(["--publish", ports_string])

    for volume_string in container.volumes:
        optional.extend(["--volume", volume_string])

    if container.log_driver:
        optional.extend(["--log-driver", container.log_driver])
        log_opts = list(f"{var}={val}" for var, val in container.log_options.items() if val and var)
        if log_opts:
            optional.extend(["--log-opt", *log_opts])

    with NamedTemporaryFile() as env_file:
        if container.env:
            optional.extend(["--env-file", env_file.name])
            for var, val in container.env.items():
                env_file.write(f"{var}={val}\n".encode("utf-8"))
            env_file.flush()
        args = [
            "docker",
            "run",
            "--detach",
            "--name",
            container.name,
            "--restart",
            "always",
            *optional,
            container.image,
            *shlex.split(container.command),
        ]
        print(" ".join(args))
        completed_process = run(args, stderr=PIPE, text=True)

        if completed_process.returncode:
            return completed_process.stderr
        return None


def update_containers_return_status(required: Dict[str, Container], existing: Dict[str, Container]) -> Status:
    """
    Main thing.
    It will stop containers that are
    1) Not on the list at all (names only compared).
    2) Have different settings.
    
    Then it will start containers that need to run.
    If it can't start container with new settings, it will try to start it with old (if it was stopped).

    Will return Status explaining what happened.
    """

    # Will store ones we killed to start with new settings
    stopped_because_of_different_settings: Dict[str, Container] = {}

    # Those should be started because they settings are different
    # We will kick them of the lift if we found matching
    should_start = required.copy()

    container_statuses: Dict[str, ContainerStatus] = {}

    for existing_container in existing.values():
        # Lets find matching container in required
        required_container = required.get(existing_container.name, None)
        if required_container:
            # Will store what have changed for logging
            changes = []
            for field in dataclasses.fields(Container):
                if field.name == "id":
                    continue
                required_field = getattr(required_container, field.name)
                existing_field = getattr(existing_container, field.name)
                if field.name == "env":
                    # For env we will check if our env is in container's
                    # So if someone only deletes env var, we will not restart.
                    for required_var, required_val in required_field.items():
                        if existing_field.get(required_var, None) != required_val:
                            changes.append(f"{field.name}: {required_field} != {existing_field}")
                            break
                else:
                    if required_field != existing_field:
                        changes.append(f"{field.name}: {required_field} != {existing_field}")

            if changes:
                print(
                    f"Stopping {existing_container.name}/{existing_container.image} because of changes: {' '.join(changes)}"
                )
                remove_container(existing_container.name)
                stopped_because_of_different_settings[existing_container.name] = existing_container
            else:
                container_statuses[required_container.name] = ContainerStatus(latest_running=True)
                del should_start[required_container.name]
        else:
            print(f"Stopping {existing_container.name}/{existing_container.image} because it is not required")
            remove_container(existing_container.name)

    for required_container in should_start.values():
        print(f"Starting {required_container.name}/{required_container.image}")
        start_error = start_container_return_error(required_container)
        if start_error:
            print(f"Failed starting {required_container}")
            print(start_error)
            stopped = stopped_because_of_different_settings.get(required_container.name)
            if stopped:
                print(f"Re-starting previously stopped {stopped}")
                restore_error = start_container_return_error(stopped)
                if restore_error:
                    print(f"Failed re-starting stopped {stopped}")
                    print(restore_error)
                    print("Damn.")
                    container_status = ContainerStatus(
                        latest_running=False,
                        latest_start_error=start_error,
                        previous_restored=False,
                        previous_restore_error=restore_error,
                    )
                else:
                    container_status = ContainerStatus(
                        latest_running=False, latest_start_error=start_error, previous_restored=True
                    )
            else:
                container_status = ContainerStatus(latest_running=False, latest_start_error=start_error)
        else:
            container_status = ContainerStatus(latest_running=True)
        container_statuses[required_container.name] = container_status

    return Status(last_update_time=int(time()), container_statuses=container_statuses)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(
            f"""
General usage:
{sys.argv[0]} <config.json> <status.json>

Will read config, update containers and write status out.

Running inside docker as a daemon:
* Put config in /etc/yards/config.json
* Set daemon=true in config
* docker run --detach --name yards --restart always --volume /var/run/docker.sock:/var/run/docker.sock --volume /etc/yards:/etc/yards metaso/yards /etc/yards/config.json /etc/yards/status.json

Running inside docker under cron:
* Set daemon=false in config
* docker run -ti --rm --volume /var/run/docker.sock:/var/run/docker.sock --volume /etc/yards:/etc/yards metaso/yards /etc/yards/config.json /etc/yards/status.json
"""
        )
        sys.exit(1)

    config_file_name, status_file_name = sys.argv[1], sys.argv[2]

    received_termination = False

    def sigterm(signum, frame):
        print(f"Got signal {signum}, finishing and quiting.")
        global received_termination
        received_termination = True

    signal.signal(signal.SIGTERM, sigterm)
    signal.signal(signal.SIGINT, sigterm)

    # We do not want to check containers too often, so we will wait wait_seconds before updates
    # and wait_seconds since the last modification of config file.
    next_update_time = int(time())
    # But we will also record last update time, and if it was too long, will update
    last_update_time = 0
    # How many seconds is too long
    TOO_LONG_SINCE_LAST_UPDATE_SECONDS = 180

    config_file = Path(config_file_name)
    config = parse_config(json.load(config_file.open()))

    while True:  # Ooh, scary.
        # We check every tick when config file was updated
        since_mtime = time() - config_file.stat().st_mtime
        # If config becomes fresh, we reset next update time to not wait more than wait_seconds since modification
        if since_mtime < config.wait_seconds:
            wait_seconds = min(config.wait_seconds - since_mtime, config.wait_seconds)
            print(f"Config was modified {since_mtime} seconds ago need to wait {wait_seconds} more before applying")
            next_update_time = int(time() + wait_seconds)

        # But we also need to be mindful if there are constant updates to not wait too long
        since_last_update_seconds = int(time() - last_update_time)
        if since_last_update_seconds > TOO_LONG_SINCE_LAST_UPDATE_SECONDS:
            if last_update_time:
                print(f"Last update was {since_last_update_seconds} seconds ago updating now")
            next_update_time = int(time())

        # Is it time to update?
        if next_update_time < time():
            config = parse_config(json.load(config_file.open()))
            print("Updating containers")
            next_update_time = int(time()) + TOO_LONG_SINCE_LAST_UPDATE_SECONDS
            existing_containers = read_existing_containers(
                ignore_labels=config.ignore_labels, ignore_images=config.ignore_images
            )
            status = update_containers_return_status(required=config.containers, existing=existing_containers)

            last_update_time = status.last_update_time

            json.dump(dataclasses.asdict(status), open(status_file_name, mode="w"), indent=2, sort_keys=True)

        if received_termination or not config.daemon:
            break
        else:
            sleep(2)
