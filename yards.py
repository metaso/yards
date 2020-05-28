#!/usr/bin/env python3

import dataclasses
from subprocess import CalledProcessError, check_output, PIPE, run, STDOUT
import json
import shlex
import sys
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional
from pprint import pprint

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


@dataclasses.dataclass
class Config:
    wait_seconds: int
    daemon: bool
    ignore_labels: List[str]
    ignore_images: List[str]
    containers: Dict[str, Container]


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


def read_existing_containers(ignore_labels: List[str], ignore_images: List[str]) -> Dict[str, Container]:
    """
    Will find what is currently running and with what parameters.
    """
    containers = {}

    # Will get just list of IDs and then inspect each
    all_ids = check_output(["docker", "ps", "--all", "--format", "{{.ID}}", "--no-trunc"]).split()
    all_inspect = json.loads(check_output(["docker", "inspect", *all_ids]))

    for inspect in all_inspect:
        config = inspect.get("Config", {}) or {}
        labels = config.get("Labels", {}) or {}
        labels_set = set(label.lower() for label in labels.keys())
        # Will ignore with labels
        if labels_set.intersection(ignore_labels):
            continue
        image = config.get("Image", "")
        # Will ignore itself
        if "metaso/yards" in image:
            continue
        # Will ignore images
        if list(i for i in ignore_images if i in image):
            continue
        host_config = inspect.get("HostConfig", {}) or {}
        network_settings = inspect.get("NetworkSettings", {}) or {}
        docker_ports = network_settings.get("Ports", {}) or {}
        docker_env = config.get("Env", []) or []

        name = inspect.get("Name", "")

        if name:
            containers[name] = Container(
                id=inspect.get("Id", ""),
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


def update_containers(required: Dict[str, Container], existing: Dict[str, Container]) -> Dict[str, Dict[str, str]]:
    """
    Main thing.
    It will stop containers that are
    1) Not on the list at all (names only compared).
    2) Have different settings.
    
    Then it will start containers that need to run.
    If it can't start container with new settings, it will try to start it with old (if it was stopped).
    """

    # Will store ones we killed to start with new settings
    stopped_because_of_different_settings: Dict[str, Container] = {}

    # Those should be started because they settings are different
    # We will kick them of the lift if we found matching
    should_start = required.copy()

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
                start_error = start_container_return_error(stopped)
                if start_error:
                    print(f"Failed re-starting stopped {stopped}")
                    print(start_error)
                    print("Damn.")

    return {"aaa": {"oooh": "eeee"}}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <config.json> <status.json>")
        sys.exit(1)

    config = parse_config(json.load(open(sys.argv[1])))
    existing_containers = read_existing_containers(ignore_labels=config.ignore_labels, ignore_images=config.ignore_images)
    status = update_containers(required=config.containers, existing=existing_containers)
    print(status)
