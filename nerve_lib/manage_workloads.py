# Copyright (c) 2024 TTTech Industrial Automation AG.
#
# ALL RIGHTS RESERVED.
# Usage of this software, including source code, netlists, documentation,
# is subject to restrictions and conditions of the applicable license
# agreement with TTTech Industrial Automation AG or its affiliates.
#
# All trademarks used are the property of their respective owners.
#
# TTTech Industrial Automation AG and its affiliates do not assume any liability
# arising out of the application or use of any product described or shown
# herein. TTTech Industrial Automation AG and its affiliates reserve the right to
# make changes, at any time, in order to improve reliability, function or
# design.
#
# Contact Information:
# support@tttech-industrial.com
# TTTech Industrial Automation AG, Schoenbrunnerstrasse 7, 1040 Vienna, Austria

"""Manage workloads on MS or LocalUi.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import Workloads
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     wl = MSWorkloads(ms_handle)
    >>>     wl_config = wl.gen_workload_configuration("docker",
    >>>                     wrkld_name="docker",
    >>>                     file_paths=["docker.tar"],
    >>>                     restart_policy="always")
    >>>     wl.provision_workload(wl_config, file_paths=["images/docker.tar"])
"""

import contextlib
import json
import logging
import os
import re
import tarfile
import time
from copy import deepcopy
from typing import Optional

import requests
import yaml
from requests_toolbelt import MultipartEncoder

from .general_utils import CheckStatusCodeError


class WorkloadDeployError(Exception):
    """Error for Deployment failed.

    msg.value: string error message
    """

    def __init__(self, message: str):
        super().__init__(message)

        self.value = message


class LocalWorkloads:
    """Manage workloads using localUI of a node.

    Parameters
    ----------
    node_handle : type
        handle to general_utils.MSNode.
    """

    def __init__(self, node_handle: type):
        self.node = node_handle
        self._log = logging.getLogger(f"Workloads-{self.node.serial_number}")

    def deploy_workload(self, file_paths: list[str], deploy_timeout: int = 300) -> type:
        """Deploy workload on node directly.

        Parameters
        ----------
        file_paths : list[str]
            Paths to files which shall be loaded.
        deploy_timeout : int, optional
            maximal time for deploying the workloads in seconds. The default is 300.

        Returns
        -------
        type
            response object of the post command.
        """
        open_files = []
        connect_error_count = 0
        accepted_status = [
            requests.codes.ok,
            requests.codes.unauthorized,
            requests.codes.no_content,
            requests.codes.conflict,
        ]
        if not self.node._add_cookies:
            self.node.login()
        while True:
            m_enc_files = {}

            if type(file_paths) is str:
                file_paths = [file_paths]

            for idx, file_path in enumerate(file_paths):
                bin_file = open(file_path, "rb")
                open_files.append(bin_file)
                m_enc_files[f"file{int(idx) + 1}" if len(file_paths) > 1 else "file"] = (
                    os.path.basename(file_path),
                    bin_file,
                    "form-data",
                )

            m_enc = MultipartEncoder(m_enc_files)

            try:
                response = self.node.post(
                    url="/api/workloads/deploy",
                    content_type=m_enc.content_type,
                    data=m_enc,
                    timeout=(7.5, deploy_timeout),
                    accepted_status=accepted_status,
                )
            except requests.exceptions.ConnectionError:
                if connect_error_count < 1:
                    connect_error_count += 1
                    self._log.warning("Received a connection error, try to login and execute command again")
                    self.node.login()
                    continue
                raise

            if response.status_code == requests.codes.unauthorized:
                self.node.login()
                accepted_status = [requests.codes.ok]
                continue

            if response.status_code == requests.codes.conflict:
                self._log.info("Workload deployment conflict - attempting deployment again.")
                time.sleep(10)
                try:
                    response = self.node.post(
                        url="/api/workloads/deploy",
                        content_type=m_enc.content_type,
                        data=m_enc,
                        timeout=(7.5, deploy_timeout),
                        accepted_status=accepted_status,
                    )
                except Exception as e:
                    if response.status_code == requests.codes.conflict:
                        self._log.error("Workload deployment failed again due to conflict.")
                        msg = "Deployment failed due to a conflict (HTTP 409) after retry."
                        raise RuntimeError(msg) from e
                    raise  # Re-raise the original exception if it's not a conflict
            break

        for bin_file in open_files:
            bin_file.close()
        self._log.info("Local Workload %s deployed", file_paths)
        return response

    def get_workload_list(self):
        """Get list of deployed workloads."""
        return self.node.get("/api/workloads", timeout=(7.5, 10)).json()

    def get_workload_details(self, workload_name):
        """Read details of a deployed workload."""
        workloads_data = self.get_workload_list()
        workload = next(wrkld for wrkld in workloads_data["workloads"] if workload_name == wrkld.get("name"))
        device_id = workload["deviceId"]
        return self.node.get(
            f"/api/workloads/{device_id}/details",
            accepted_status=[requests.codes.ok],
        ).json()

    def control(self, workload_name: str, command: str, remove_images: bool = True) -> None:
        """Control the workload status.

        Parameters
        ----------
        workload_name : str
            Workload to be controlled.
        command : str
            Command can be one of START, STOP, SUSPEND, RESUME, RESTART, UNDEPLOY".
        """
        workloads_data = self.get_workload_list()
        workload = next(wrkld for wrkld in workloads_data["workloads"] if workload_name == wrkld.get("name"))
        device_id = workload["deviceId"]
        payload = {
            "workloadId": workload["workloadId"],
        }
        if command.upper() == "UNDEPLOY":
            payload["removeImages"] = remove_images

        return self.node.put(f"/api/workloads/{device_id}/control/{command.upper()}", json=payload)

    def undeploy(self, workload_name: str = "", remove_images: bool = True):
        """Undeploy workload.

        If no workload_name is defined, all workloads are undeployed.
        """
        if workload_name:
            self.control(workload_name, "UNDEPLOY", remove_images)
        else:
            workloads_data = self.get_workload_list()
            for wrkld in workloads_data["workloads"]:
                self.control(wrkld["name"], "UNDEPLOY", remove_images)

    def import_volume_data(self, volume_name, file, import_timeout=30):
        """Import data to a volume.

        Parameters
        ----------
        volume_name : str
            Name of the volume.
        file : str
            Path to the file to be imported.
        """
        m_enc = MultipartEncoder({"file": (os.path.basename(file), open(file, "rb"), "form-data")})

        return self.node.post(
            url=f"/api/docker-resources/volumes/{volume_name}/import",
            content_type=m_enc.content_type,
            data=m_enc,
            accepted_status=[requests.codes.ok],
            timeout=(30, import_timeout),
        )

    def export_volume_data(self, volume_name, export_timeout=30):
        """Import data to a volume.

        Parameters
        ----------
        volume_name : str
            Name of the volume.
        """
        return self.node.get(
            url=f"/api/docker-resources/volumes/{volume_name}/export",
            stream=True,
            accepted_status=[requests.codes.ok],
            timeout=export_timeout,
        )


class MSWorkloads:
    """Manage workloads on a MS.

    Parameters
    ----------
    ms_handle : type
        handle of general_utils.MSHandle.
    """

    API_V1 = 1
    API_V2 = 2
    API_V3 = 3

    def __init__(self, ms_handle: type):
        self.ms = ms_handle
        self._log = logging.getLogger("Workloads")

    def provision_workload(
        self,
        payload: dict,
        file_paths: list[str] = [],
        api_version: int = 2,
        patch_version: bool = True,
        registry_download_timeout: int = 400,
    ) -> None:
        """Provision a new workload to the MS.

        Parameters
        ----------
        payload : dict
            workload description file, generated with Workloads.gen_workload_configuration(...).
        file_paths : list[str], optional
            pathes to the workload related files. The default is [].
        api_version : int, optional
            API version to be used, one of 1, 2, 3. The default is 2.
        patch_version : bool, optional
            If set, existing workload with same name/version will be patched. The default is True.
        registry_download_timeout : int, optional
            Maximal download time of a registry workload. The default is 400.
        """
        if api_version == self.API_V1:
            self.__send_provision_workload("/nerve/workload", file_paths, payload, False)
        elif api_version in {self.API_V2, self.API_V3}:
            update_workload = False
            wl_version = self.WorkloadVersion(
                payload["name"],
                payload["versions"][0]["name"],
                payload["versions"][0].get("releaseName", None),
            )
            try:
                workload_id = wl_version._get_workload_id()

                payload["_id"] = workload_id
                update_workload = True

                if payload["type"] == "docker" and api_version == self.API_V3:
                    _, version_id = wl_version._get_ids(api_version=self.API_V3)
                _, version_id = wl_version._get_ids()

                if patch_version:
                    wl_version._log.info("Patching workload version")
                    payload["versions"][0]["_id"] = version_id
                elif api_version != self.API_V3:
                    wl_version._log.info("workload and version already exists, skipping provisioning")
                    return

            except ValueError:
                if update_workload:
                    wl_version._log.info("Creating a new version")
                else:
                    wl_version._log.info("Creating a new workload")

            if api_version == self.API_V2:
                self.__send_provision_workload(
                    "/nerve/v2/workloads",
                    file_paths,
                    payload,
                    update_workload,
                    registry_download_timeout,
                )
            elif payload["type"] == "docker" and api_version == self.API_V3:
                # Step 1: Create Workload
                self.provision_compose_workload(payload, update_workload)
                # Step2: Create Version
                wl_version.create_compose_version(payload["versions"][0], patch_version)
                # Step3: Upload files
                wl_version.set_compose_repo(file_paths, type="docker")

            elif api_version == self.API_V3 and payload["type"] == "docker-compose":
                # docker compose workload only

                # Step 1: Create Workload
                self.provision_compose_workload(payload, update_workload)

                # Step2: Create Version
                wl_version.create_compose_version(payload["versions"][0], patch_version)

                # Step3: Upload files
                for file_path in file_paths:
                    if type(file_path) is str and os.path.splitext(file_path)[-1] in {".yaml", ".yml"}:
                        with open(file_path, "r", encoding="utf-8") as file:
                            compose_content = yaml.safe_load(file)
                        wl_version.set_compose_content(
                            compose_content,
                            os.path.split(file_path)[-1],
                            patch_version,
                        )

                # Step4: Upload image file(s)
                for file_path in file_paths:
                    if type(file_path) is str:
                        if os.path.splitext(file_path)[-1] == ".tar":
                            wl_version.set_compose_image(file_path, patch_version)
                    elif type(file_path) is dict:
                        wl_version.set_compose_repo(
                            file_path.get("repo"),
                            file_path.get("user", ""),
                            file_path.get("password", ""),
                        )

                # Step5: Check deployable state
                wl_version.get_compose_deployable_state(registry_download_timeout)

        else:
            msg = f"API version {api_version} is not implemented"
            raise RuntimeError(msg)

    def __send_provision_workload(
        self,
        endpoint_url: str,
        file_paths: list,
        payload: dict,
        update_workload: bool,
        registry_download_timeout: int = 400,
    ) -> None:
        """Execte provision command.

        Parameters
        ----------
        endpoint_url : str
            depending on the used API, a different URL is used.
        file_paths : list
            List of files for the workload.
        payload : dict
            post command payload.
        update_workload : bool
            if set, workloads will be updated (e.g. new version will be created).
        registry_download_timeout : int, optional
            Download timeout for loading docker registry
        """
        kwargs_provision = {
            "url": endpoint_url,
            "json": deepcopy(payload),
            "timeout": (7.5, 30000),
            "accepted_status": [requests.codes.ok, requests.codes.forbidden],
        }

        open_files = []
        connect_error_count = 0
        while True:  # noqa: PLR1702
            if type(file_paths) is str:
                file_paths = [file_paths]

            m_enc_files = {}
            if "versions" in payload:
                if "files" in payload["versions"][0]:
                    for str_idx, content in payload["versions"][0]["files"].items():
                        file_path = ""
                        for fpath in file_paths:
                            if fpath.endswith(content["originalName"]):
                                file_path = fpath

                        if file_path:
                            self._log.debug("Opening File %s", file_path)
                            bin_file = open(file_path, "rb")
                            open_files.append(bin_file)

                            m_enc_files[
                                f"file{int(str_idx) + 1}"
                                if len(payload["versions"][0]["files"]) > 1
                                else "file"
                            ] = (
                                content["originalName"],
                                bin_file,
                                "form-data",
                            )

                data = {"data": (None, json.dumps(payload), "form-data")}
                data |= m_enc_files
                m_enc = MultipartEncoder(data)
                kwargs_provision |= {
                    "content_type": m_enc.content_type,
                    "data": m_enc,
                }

            try:
                if update_workload:
                    if "internalDockerRegistry" in kwargs_provision["json"]:
                        # InternalDockerRegistry cant be changed, so we need to remove it from the payload for updating the workload
                        del kwargs_provision["json"]["internalDockerRegistry"]
                    response = self.ms.patch(**kwargs_provision)
                else:
                    if requests.codes.conflict not in kwargs_provision["accepted_status"]:
                        kwargs_provision["accepted_status"].append(requests.codes.conflict)
                    if self.ms.version_smaller_than("2.10.0"):
                        if "internalDockerRegistry" in kwargs_provision["json"]:
                            # InternalDockerRegistry is not supported with MS version < 2.10.0
                            del kwargs_provision["json"]["internalDockerRegistry"]
                    response = self.ms.post(**kwargs_provision)
                    if response.status_code == requests.codes.conflict:
                        self.ms._log.warning(
                            "Workload with same name already exists. Assuming the workload was already deployed"
                            " before",
                        )
                if response.status_code == requests.codes.forbidden:
                    self.ms.login()
                    if requests.codes.forbidden in kwargs_provision["accepted_status"]:
                        kwargs_provision["accepted_status"].pop(
                            kwargs_provision["accepted_status"].index(requests.codes.forbidden),
                        )
                    continue
                break
            except requests.exceptions.ConnectionError:
                if connect_error_count < 1:
                    connect_error_count += 1
                    self._log.warning("Received a connection error, try to login and execute command again")
                    self.ms.login()
                    continue
                raise

        for bin_file in open_files:
            bin_file.close()

        if "versions" in payload:
            version_name = payload["versions"][0]["name"]
            version_release_name = payload["versions"][0].get("releaseName")
            self.ms._log.info("Provisioned workload '%s/%s'", payload["name"], version_name)
            if payload["versions"][0].get("dockerFileOption", "") == "path":
                self.ms._log.info("Waiting for docker registry workload to be loaded from server...")
                workload_id = self.WorkloadVersion(payload["name"])._get_workload_id()

                time_start = time.time()
                while time.time() - time_start < registry_download_timeout:
                    response = self.ms.get(
                        url=f"/nerve/v2/workloads/{workload_id}",
                        accepted_status=[requests.codes.ok],
                    ).json()
                    version = next(
                        vers
                        for vers in response["versions"]
                        if vers["name"] == version_name and vers.get("releaseName") == version_release_name
                    )
                    if version["isDeployable"] is True:
                        self.ms._log.info("Docker workload from registry provisioned!")
                        return
                    if version["isDownloading"] is False:
                        break
                    time.sleep(10)
                self.ms._log.warning("Docker workload from registry NOT provisioned!")
        elif "name" in payload:
            self.ms._log.info("Provisioned workload '%s'", payload["name"])
        else:
            self.ms._log.info("Workload provision response: %s", response.json())
        time.sleep(5)  # Allow the MS to finish provisioning steps

    def __fix_workload_config_v1_networks(self, networks):
        """Validate and fix 'networks' input."""
        if type(networks) is list:
            self._log.warning("API V1 requires networks definition as a string, reformatting...")
            return ",".join(networks)
        return networks

    def __fix_workload_config_v2_networks(self, networks):
        """Validate and fix 'networks' input."""
        if type(networks) is str:
            self._log.warning(
                "Provide networks as a list of ['network1', ...]. Tryping to reformat from string...",
            )
            networks = networks.split(",")
        return networks

    def __fix_workload_config_v1_ports(self, ports):
        """Validate and fix 'ports' input."""
        if type(ports) is list:
            self._log.warning("API V1 requires ports definition as a string, reformatting...")

            ports_str_list = []
            for port_cfg in ports:
                ports_str_list.append(
                    f"{port_cfg['host_port']}={port_cfg['container_port']}/{port_cfg.get('protocol', 'UDP')}",
                )

            return "\n".join(ports_str_list)

        return ports

    def __fix_workload_config_v2_ports(self, ports):
        """Validate and fix 'ports' input."""
        if type(ports) is str:
            if not ports:
                ports = []
            else:
                self._log.warning(
                    "Provide networks as a list of [{'protocol': str.upper(), 'host_port': int, 'container_port': int}, ...]. Trying to reformat from string... ",
                )
                ports_new = []
                for port_cfg in ports.split("\n"):
                    port_protocol = port_cfg.split("/")[1]  # tcp or udp
                    ports_list = port_cfg.split("/")[0].split("=")
                    ports_new.append({
                        "protocol": port_protocol.upper(),
                        "host_port": int(ports_list[0]),
                        "container_port": int(ports_list[1]),
                    })
                ports = ports_new
        elif type(ports) is list:
            for port in ports:
                if "protocol" in port:
                    port["protocol"] = port["protocol"].upper()

        return ports

    def __fix_workload_config_v1_docker_volumes(self, docker_volumes):
        """Validate and fix 'docker_volumes' input."""
        if type(docker_volumes) is list:
            self._log.warning("API V1 requires docker_volumes definition as a string, reformatting...")
            docker_vols_new = []
            for docker_vol in docker_volumes:
                docker_vols_new.append(f"{docker_vol['volumeName']}:{docker_vol['containerPath']}")
            return "\n".join(docker_vols_new)
        return docker_volumes

    def __fix_workload_config_v2_docker_volumes(self, docker_volumes):
        """Validate and fix 'docker_volumes' input."""
        if type(docker_volumes) is str:
            if not docker_volumes:
                docker_volumes = []
            else:
                self._log.warning(
                    "Provide docker_volumes as a list of [{'volumeName': str, 'containerPath': str, 'configurationStorage': bool}, ...]. Trying to reformat from"
                    " string... ",
                )
                docker_vols_new = []
                for docker_vol in docker_volumes.split("\n"):
                    docker_vols_new.append({
                        "volumeName": docker_vol.split(":")[0],
                        "containerPath": docker_vol.split(":")[1],
                        "configurationStorage": False,
                    })
                docker_volumes = docker_vols_new
        return docker_volumes

    def __fix_workload_config_v1_env_var(self, env_var):
        """Validate and fix 'env_var' input."""
        if type(env_var) is list:
            self._log.warning("API V1 requires env_var definition as a string, reformatting...")
            env_var_new = []
            for env in env_var:
                env_var_new.append(f"{env['env_variable']}={env['container_value']}")
            return "\n".join(env_var_new)
        return env_var

    def __fix_workload_config_v2_env_var(self, env_var):
        """Validate and fix 'env_var' input."""
        if type(env_var) is str:
            if not env_var:
                env_var = []
            else:
                self._log.warning(
                    "Provide env_var as a list of [{'env_variable': str, 'container_value': str}, ...]. Trying to reformat from string... ",
                )
                env_var_new = []
                for env in env_var.split("\n"):
                    env_var_new.append({
                        "env_variable": env.split("=")[0],
                        "container_value": env.split("=")[1],
                    })
                env_var = env_var_new
        return env_var

    def __fix_workload_config_v2_vm_memory(self, vm_memory):
        """Validate and fix 'vm_memory' input."""
        if type(vm_memory) is str:
            self._log.warning(
                "Provide vm_memory as a dict {'unit': str, 'value' int}. Trying to reformat from string... ",
            )
            memory = re.findall(r"([0-9]+)([A-Z]+)", vm_memory)
            vm_memory = {"unit": memory[0][1], "value": int(memory[0][0])}
        return vm_memory

    def gen_workload_configuration(  # noqa: PLR0913, PLR0917
        self,
        provision_type: str,
        file_paths: list[str] = "",
        wrkld_name: str = "test_workload",
        wrkld_version_name: str = "test_version",
        container_name: str = "test_container",
        release_name: str = "",
        description: str = "",
        label: list = [],
        networks: list = ["bridge"],
        ports: list[dict] = [],
        docker_volumes: list[dict] = [],
        restart_on_config_update: bool = False,
        env_var: list[dict] = "",
        remote_connections: list[dict] = [],
        restart_policy: str = "no",
        limit_cpus: Optional[str] = None,
        limit_memory: Optional[dict] = None,
        released: bool = False,
        auth_usr: str = "",
        auth_psw: str = "",
        vm_num_cpus: int = 1,
        vm_memory: dict = {"unit": "MB", "value": 700},
        vm_snapshot: dict = {"enabled": False},
        compose_dict: dict = {},
        docker_config_volumes: list = [],
        api_version: int = 2,
        internal_docker_registry: bool = False,
    ) -> dict:
        """Provision of Docker.

        Parameters
        ----------
        provision_type : str
            One of "docker", "registry", "vm", "codesys", "docker-compose"
        file_paths : str/list
            Files to be added to option "file: {}"
            'vm' workload requires img and xml file to be defined
        wrkld_name : str, optional
            Name of workload. The default is "test_workload".
        wrkld_version_name : str, optional
            Name of workload version. The default is "test_version".
        container_name : str, optional
            Docker container name.. The default is "test_container".
        release_name : str, optional
            Name of the release version. The default is wrkld_version_name.
        description : str, optional
            Description of Workload
        label : str, optional
            Labels to be defined for a workload
        networks : str, optional
            Docker workload networks. The default is ["bridge"].
            for vm type set network similar to this example:
                [{"type":"NAT","interface":"default"},
                {"type":"Bridged","interface":"isolated1"}]
        ports : str, optional
            Port binding for docker workload. The default is "".
            api1: str (e.g. "80:8080/tcp")
            api2: List of dict [{'protocol':'TCP','host_port': 80, 'container_port': 8080}]
        docker_volumes : str/list, optional
            mapped volumes in docker workload. The default is "".
            api1: volumes defined as string(e.g. "NGINX_1:/var/www/nginx")
            api2: list of dict {"volumeName": str, "containerPath": str,  "configurationStorage": bool}
        restart_on_config_update : bool, optional
            Restart container on confuration update (of docker-volume with "configurationStorage: True")
        env_var : string/list, optional
            environment variables in docker workload. The default is "".
            api1: string (e.g. LOG_LEVEL=Info)
            api2: list of dict {"env_variable": str, "container_value": str}
        remote_connections : list, optional
            List of remote connections. The default is [].
            List is a dict {"type": "TUNNEL or SCREEN",
                            "name": str,
                            "acknowledgment": "No or Yes",.
                            "serviceName": Required for compose workload only, name of the service
                            "hostname": ip-address
                            "port": int,
                            "localPort": int}
        restart_policy : str, optional
            Container restart policy (no, on-failure, always, unless-stopped). The default is "no"
        limit_cpus : str, optional
            Set CPU limit for workload
        limit_memory : dict, optional
            Set Memory limit for workload (e.g. {"unit": "MB", "value": 256})
        vm_snapshot : dict, optional
            Set snapshot configuration for VM workload (user-permission 'VM workload snapshot' required)
        released : bool, optional
            Mark workload as released version
        aut_usr, aut_psw : str, optional
            In case of file_option == "file" (registry workload) it is possible to define login credentials
        compose_dict: dict, optional
            docker-compose only: docker compose file as dict
        docker_config_volumes : list, optional
            docker-compose only: list of dict e.g. [{"service": xyz, "volume_id": 0, "restart_on_update": False}]
        api_version : int, 1,2 or 3
            Default is 2- APIv1 does not support PATCH'ing workloads with new versions.

        """
        """Common payload elements for v1 and v2 workload endpoint payloads"""

        if type(file_paths) is str:
            file_paths = [file_paths]

        files = {}
        for idx, file_path in enumerate(sorted(file_paths, key=lambda file: os.path.splitext(file)[1])):
            files[f"{idx}"] = {"originalName": os.path.split(file_path)[-1]}

        if not release_name:
            release_name = wrkld_version_name

        payload = {
            "type": "docker" if provision_type in {"registry", "docker-internal"} else provision_type,
            "name": wrkld_name[:40],
            "description": description,
            "versions": [
                {
                    "name": wrkld_version_name[:40],
                    "releaseName": release_name[:40],
                    "selectors": label,
                },
            ],
        }
        if api_version == self.API_V1:
            networks = self.__fix_workload_config_v1_networks(networks)
            ports = self.__fix_workload_config_v1_ports(ports)
            docker_volumes = self.__fix_workload_config_v1_docker_volumes(docker_volumes)
            env_var = self.__fix_workload_config_v1_env_var(env_var)
        if api_version in {self.API_V2, self.API_V3}:
            networks = self.__fix_workload_config_v2_networks(networks)
            ports = self.__fix_workload_config_v2_ports(ports)
            docker_volumes = self.__fix_workload_config_v2_docker_volumes(docker_volumes)
            env_var = self.__fix_workload_config_v2_env_var(env_var)
            payload["internalDockerRegistry"] = internal_docker_registry
            if provision_type == "vm":
                vm_memory = self.__fix_workload_config_v2_vm_memory(vm_memory)

            # Updating workload with v2 endpoint which is structured differently to v1 endpoint.
            payload["disabled"] = False
            payload["deleted"] = False

            properties_name = "workloadProperties"

        else:
            properties_name = "generalDataSection"
            payload["status"] = "new"

        payload["versions"][0] |= {
            "released": released,
            "deleted": False,
            "remoteConnections": remote_connections,
        }

        if provision_type not in {"docker-compose", "registry"}:
            payload["versions"][0] |= {"files": files}

        if provision_type != "docker-compose":
            payload["versions"][0][properties_name] = {}
            if limit_cpus and provision_type not in {"vm", "codesys"}:
                payload["versions"][0][properties_name]["limit_CPUs"] = limit_cpus
            if limit_memory and provision_type not in {"vm", "codesys"}:
                payload["versions"][0][properties_name]["limit_memory"] = limit_memory

        if provision_type == "registry" and auth_usr:
            if api_version == self.API_V1:
                payload["versions"][0][properties_name]["auth-credentials"] = (
                    f"username:{auth_usr},password:{auth_psw}"
                )
            else:
                payload["versions"][0][properties_name]["auth_credentials"] = {
                    "username": auth_usr,
                    "password": auth_psw,
                }
        if provision_type in {"registry", "docker"}:
            payload["versions"][0] |= {
                "dockerFileOption": "path" if provision_type == "registry" else "file",
                "dockerFilePath": file_paths[0] if provision_type == "registry" else "",
                "restartOnConfigurationUpdate": restart_on_config_update,
            }
            payload["versions"][0][properties_name] |= {
                "docker_volumes": docker_volumes,
                "container_name": container_name,
                "port_mappings_protocol": ports,
                "environment_variables": env_var,
                "networks": networks,
                "restart_policy": restart_policy,
            }
        if provision_type == "vm":
            payload["versions"][0][properties_name] |= {
                "data_disks": "[]" if api_version == self.API_V1 else [],
                "libvirt_networks": str(networks) if api_version == self.API_V1 else networks,
                "no_of_vCPUs": vm_num_cpus,
                "memory": vm_memory,
            }
            if api_version == self.API_V2:
                payload["versions"][0] |= {"capabilities": []}
                payload["versions"][0][properties_name] |= {
                    "snapshot": vm_snapshot,
                    "PCI_passthrough": [],
                }
        if provision_type == "docker-compose":
            config_storage = None
            payload["versions"][0]["workloadSpecificProperties"] = {"dockerConfigurationStorage": []}
            for docker_config in docker_config_volumes:
                try:
                    docker_config_volume = compose_dict["services"][docker_config["service"]]["volumes"][
                        int(docker_config.get("volume_id", 0))
                    ]
                except KeyError:
                    self._log.error(
                        "Key Error, available services in docker file: %s",
                        compose_dict["services"].keys(),
                    )
                    raise
                config_storage = {
                    "containerPath": docker_config_volume.split(":")[1],
                    "volumeName": docker_config_volume.split(":")[0],
                    "serviceName": docker_config["service"],
                    "restartOnConfigurationUpdate": bool(docker_config.get("restart_on_update", False)),
                }
                payload["versions"][0]["workloadSpecificProperties"]["dockerConfigurationStorage"].append(
                    deepcopy(config_storage),
                )
            del payload["deleted"]
            del payload["versions"][0]["deleted"]
            del payload["versions"][0]["releaseName"]
        if provision_type == "docker-internal":
            config_storage = None
            del payload["deleted"]
            payload["versions"][0] = {}
            payload["versions"][0]["name"] = wrkld_version_name
            payload["versions"][0]["released"] = released
            payload["versions"][0]["selectors"] = label
            payload["versions"][0]["remoteConnections"] = remote_connections
            payload["versions"][0]["workloadSpecificProperties"] = {
                "port_mappings_protocol": ports,
                "environment_variables": env_var,
                "limit_memory": limit_memory if limit_memory is not None else {},
                "limit_CPUs": limit_cpus if limit_cpus is not None else "",
                "container_name": container_name,
                "networks": networks,
                "restart_policy": restart_policy,
                "docker_volumes": docker_volumes,
                "auth_credentials": {
                    "username": auth_usr,
                    "password": auth_psw,
                },
            }
        return payload

    def get_workloads_dict(self, read_versions=True, read_compose_details=True, compact_dict=True) -> dict:
        """Read workloads list of MS.

        Returns
        -------
        dict
            dict of {workload-name: [version, release_version]}.
        """
        workload_list = {}
        workloads = (
            self.ms.get("/nerve/v2/workloads", params={"limit": 200}, accepted_status=[requests.codes.ok])
            .json()
            .get("data", [])
        )
        if not read_versions:
            if compact_dict:
                return [wrkld["name"] for wrkld in workloads]
            return workloads
        for workload in workloads:
            workload_id = workload.get("_id")
            if workload.get("type") == "docker-compose" or (
                workload.get("type") == "docker" and workload.get("internalDockerRegistry")
            ):
                versions = (
                    self.ms.get(
                        f"/nerve/v3/workloads/{workload_id}/versions",
                        accepted_status=[requests.codes.ok],
                    )
                    .json()
                    .get("data")
                )
                if read_compose_details:
                    # Validate if details can be read from workload
                    for version in versions:
                        try:
                            self.ms.get(
                                f"/nerve/v3/workloads/{workload_id}/versions/{version['_id']}",
                                accepted_status=[requests.codes.ok],
                            )
                        except CheckStatusCodeError as ex_msg:
                            msg = f"Workload {workload.get('name')}-{version.get('name')}: {ex_msg.value}"
                            raise CheckStatusCodeError(
                                msg,
                                ex_msg.status_code,
                                ex_msg.response_text,
                            )

            else:
                versions = (
                    self.ms.get(f"/nerve/v2/workloads/{workload_id}", accepted_status=[requests.codes.ok])
                    .json()
                    .get("versions")
                )
            if compact_dict:
                workload_list[workload.get("name")] = []
                for version in versions:
                    workload_list[workload.get("name")].append([
                        version.get("name"),
                        version.get("releaseName", ""),
                    ])
            else:
                workload["versions"] = versions
        if compact_dict:
            return workload_list
        return workloads

    def provision_compose_workload(self, payload: dict, update_workload: bool):
        """Create new docker-compose workload.

        Parameters
        ----------
        payload : dict
            workload description file, generated with Workloads.gen_workload_configuration(...).
        update_workload : bool
            Patch the workload with new paramters, if set to false, the workload will only be created, not changed.
        """
        payload1 = deepcopy(payload)
        del payload1["versions"]
        api_v3_path = "/nerve/v3/workloads"
        if update_workload:
            api_v3_path = f"/nerve/v3/workloads/{payload1['_id']}"
            del payload1["_id"]
            del payload1["type"]
        self.__send_provision_workload(api_v3_path, [], payload1, update_workload)

    def check_for_deployment_state(
        self,
        deploy_name: str,
        state: Optional[str] = None,
        timeout: int = 400,
        check_interval: int = 60,
    ) -> dict:
        """Verify deployment state of a workload.

        Function will wait until deployment reaches a defined state (e.g. inProgress, isFinished, ...)
        if state = None, the current state will just be printed.

        Parameters
        ----------
        deploy_name : str
            name of the deployment task on the MS.
        state : str, optional
            state which shall be checked. The default is None.
        timeout : int, optional
            Maximal time until the state shall be present. The default is 400.
        check_interval : int, optional
            Interval in seconds the deployment state shall be checked on. The default is 30.

        Returns
        -------
        dict
            Deployment state information when command is finished.
        """
        status = {}
        time_start = time.time()
        time_last_log_print = time_start
        status_old = []
        while (time.time() - time_start) < timeout:
            dep_logs = self.ms.get(
                "/bom/deployment/list",
                params={"contentType": "workload", "limit": 100, "page": 1},
                accepted_status=[requests.codes.ok],
                timeout=(7.5, 10),
            ).json()
            dep_log = next(
                (
                    dep_log
                    for dep_log in dep_logs.get("data", [])
                    if dep_log.get("operation_name") == deploy_name
                ),
                None,
            )
            if not dep_log:
                self.ms._log.warning("Deployment %s not found, retrying... ", deploy_name)
                time.sleep(5)
                continue

            for value in ["inProgress", "isFinished", "isSuccess", "isFailed"]:
                status[value] = dep_log.get(value)

            if dep_log.get("inProgress"):
                num_failed_tasks = 0

                status_new = []
                detail_status = self.ms.get(
                    f"/bom/task/getDeployTasksInDeployment/{dep_log.get('_id')}",
                    accepted_status=[requests.codes.ok],
                ).json()

                for feedback in detail_status.get("data", []):
                    task_options = feedback.get("taskOptions")
                    status_new.append(task_options.get("status"))
                    if task_options.get("status").upper() == "ERROR":
                        num_failed_tasks += 1

                if time.time() - time_last_log_print > check_interval or status_old != status_new:
                    # Print status every check_interval seconds or if status has changed
                    time_last_log_print = time.time()
                    status_old = deepcopy(status_new)
                    self.ms._log.info(
                        "%3s/%3s Deployment %s in progress [%.0f %%]",
                        int(time.time() - time_start),
                        timeout,
                        deploy_name,
                        dep_log.get("campaignOptions", {}).get("progress"),
                    )

                    for feedback in detail_status.get("data", []):
                        task_options = feedback.get("taskOptions")
                        self._log.info(
                            " - Node %s: [ Status: %s, Progress: %s%% ]",
                            feedback.get("device"),
                            task_options.get("status"),
                            task_options.get("progress"),
                        )

                        if task_options.get("status").upper() == "ERROR":
                            self.ms._log.error(
                                " - Node %s Error-details: %s",
                                feedback.get("device"),
                                json.dumps(feedback["errorFeedback"], indent=4),
                            )

                if num_failed_tasks == len(detail_status.get("data")):
                    self._log.error(
                        "Overall Status is in progress, but all workload deployments have failed",
                    )
                    return status

            if dep_log.get("isFailed"):
                detail_status = self.ms.get(
                    f"/bom/task/getDeployTasksInDeployment/{dep_log.get('_id')}",
                    accepted_status=[requests.codes.ok],
                ).json()
                self.ms._log.error("Deployment of %s failed", deploy_name)
                for feedback in detail_status.get("data", []):
                    self.ms._log.error(
                        " - Node %s Error-details: %s",
                        feedback.get("device"),
                        json.dumps(feedback["errorFeedback"], indent=4),
                    )

                return status
            if dep_log.get("isFinished"):
                return status

            if state is None:
                return status
            if dep_log.get(state):
                self.ms._log.info("Deployment is in expected state (%s)", state)
                return status

            time.sleep(min(check_interval, 5))
        self.ms._log.warning("Deployment timeout (%d sec) reached", timeout)
        return status

    def validate_compose_content(self, content: dict, file_name: str = "compose-file.yaml") -> dict:
        """Validate if the content of a compose-file is valid."""
        yml_file = yaml.dump(content, indent=4, default_flow_style=False, sort_keys=False)
        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        while True:
            m_enc = MultipartEncoder({
                "type": "compose",
                "origin": "upload",
                "source": "file",
                "file": (file_name, yml_file, "form-data"),
            })
            resp = self.ms.post(
                "/nerve/v3/workloads/compose",
                accepted_status=accepted_status,
                data=m_enc,
                content_type=m_enc.content_type,
            )

            if resp.status_code == requests.codes.forbidden:
                self.ms.login()
                accepted_status = [requests.codes.ok]
                continue
            return resp.json()

    def WorkloadVersion(self, workload_name: str, version: str = "", release_version: str = ""):
        """Handle to specific workload of a MS.

        Parameters
        ----------
        workload_name : str
            selected workload name.
        version : str, optional
            selected workload version. If empty, the last version will be selected. The default is "".
        release_version : str, optional
            selected release version. If empty, the last version will be selected. The default is "".

        Returns
        -------
        TYPE
            Handle to _WorkloadVersion class.
        """
        return _WorkloadVersion(self, workload_name, version, release_version)


class _WorkloadVersion:  # noqa: PLR0904
    """Handle to specific workload of a MS.

    Parameters
    ----------
    owner : type
        handle to manage_workloads.Workloads object.
    workload_name : str
        selected workload name.
    version : str, optional
        selected workload version. If empty, the last version will be selected. The default is "".
    release_version : str, optional
        selected release version. If empty, the last version will be selected. The default is "".
    """

    def __init__(self, owner: type, workload_name: str, version: str = "", release_version: str = ""):
        self.workload_name = workload_name
        self.version = version
        self.release_version = release_version

        self.owner = owner
        if version:
            self._log = logging.getLogger(f"{workload_name}/{version}")
        elif release_version:
            self._log = logging.getLogger(f"{workload_name}/{release_version}")
        else:
            self._log = logging.getLogger(f"{workload_name}/latest")

        # Values beeing updated on demand, default to None to verify if they had been updated already
        self.__workload_type = None
        self.__workload_id = None
        self.__version_id = None

    def _get_workload_type(self, expected_type="") -> str:
        """Get workload type."""
        if not self.__workload_type:
            self._get_workload().get("type")  # Update self.__workload_type and self.__workload_id
        if expected_type and expected_type != self.__workload_type:
            msg = f"Workload type {expected_type} required, but workload is of type {self.__workload_type}"
            raise RuntimeError(
                msg,
            )
        return self.__workload_type

    def _get_workload(self) -> dict:
        """Read workkoad information.

        Returns
        -------
        dict
            MS API response containing worklaad information.
        """
        workloads = self.owner.ms.get(
            "/nerve/v2/workloads",
            params={"limit": 200},
            accepted_status=[requests.codes.ok],
        ).json()
        try:
            selected_workload = next(
                workload
                for workload in workloads.get("data", [])
                if workload.get("name") == self.workload_name
            )
            self.__workload_type = selected_workload["type"]
            self.__workload_id = selected_workload["_id"]
        except StopIteration:
            msg = f"Workload with name {self.workload_name} was not found in list"
            raise ValueError(msg)
        return selected_workload

    def _get_versions(self, selected_version=False, api_version=2) -> dict:
        """Read list of available workload versions.

        Parameters
        ----------
        selected_version : bool, optional
            If set, only the version object matching the workload class will be returned

        Returns
        -------
        dict
            workload version information.
        """
        workload_id = self._get_workload_id()

        if self._get_workload_type() == "docker-compose":
            versions = (
                self.owner.ms.get(
                    f"/nerve/v3/workloads/{workload_id}/versions",
                    accepted_status=[requests.codes.ok],
                )
                .json()
                .get("data")
            )
        elif self._get_workload_type() == "docker" and api_version == self.owner.API_V3:
            versions = (
                self.owner.ms.get(
                    f"/nerve/v3/workloads/{workload_id}/versions",
                    accepted_status=[requests.codes.ok],
                )
                .json()
                .get("data")
            )
        else:
            versions = (
                self.owner.ms.get(f"/nerve/v2/workloads/{workload_id}", accepted_status=[requests.codes.ok])
                .json()
                .get("versions")
            )
        if selected_version:
            if self.version:
                versions = list(filter(lambda x: x.get("name") == self.version, versions))
            if self.release_version:
                versions = list(filter(lambda x: x.get("releaseName") == self.release_version, versions))
            if len(versions) == 0:
                msg = f"Workload version {self.version} - {self.release_version} does not exist"
                raise ValueError(msg)
            self.__version_id = versions[-1]["_id"]
            return versions[-1:]
        return versions

    def _get_workload_id(self) -> str:
        """Read workload id."""
        if not self.__workload_id:
            self._get_workload()  # Update self.__workload_type and self.__workload_id
        return self.__workload_id

    def _get_ids(self, api_version=2) -> tuple[str, str]:
        """Read workload and version id.

        Returns
        -------
        tuple[str, str]
            tuple containing workload_id, version_id.
        """
        workload_id = self._get_workload_id()

        if not self.__version_id:
            self._get_versions(selected_version=True, api_version=api_version)  # Update self.__version_id

        return workload_id, self.__version_id

    def get_container(self, include_version=True) -> dict:
        """Read workload container information.

        Returns
        -------
        dict
            information representing the selected workload and version.
        """
        workload = self._get_workload()
        workload["versions"] = []
        if include_version:
            version = self._get_versions(selected_version=True)
            workload["versions"] = [version]

        return workload

    def mod_container(self, container_version: dict) -> type:
        """Modify existing workload container.

        Parameters
        ----------
        container_version : dict
            new container dict, modified from get_container().
        """
        workload_id, version_id = self._get_ids()
        if self._get_workload_type() == "docker-compose":
            workload_info = {}
            for key, default in (("name", self.workload_name), ("description", ""), ("disabled", False)):
                workload_info[key] = container_version.get(key, default)

            self._log.info("Patching workload with APIv3 (workload-info): %s", workload_info)
            self.owner.ms.patch(
                f"/nerve/v3/workloads/{workload_id}",
                json=workload_info,
                accepted_status=[requests.codes.ok],
            )

            if container_version.get("versions"):
                version_info = {}
                for key, default in (
                    ("name", self.version),
                    ("released", False),
                    ("workloadSpecificProperties", {}),
                    ("selectors", []),
                    ("remoteConnections", []),
                ):
                    version_info[key] = container_version["versions"][0].get(key, default)
                self._log.debug("Patching workload with APIv3 (version-info): %s", version_info)
                self.owner.ms.patch(
                    f"/nerve/v3/workloads/{workload_id}/versions/{version_id}",
                    json=version_info,
                    accepted_status=[requests.codes.ok],
                )
        elif container_version.get("versions"):
            self._log.debug("Patching workload including version with APIv2")
            accepted_status = [requests.codes.ok, requests.codes.forbidden]
            while True:
                m_enc = MultipartEncoder({"data": (None, json.dumps(container_version), "form-data")})
                resp = self.owner.ms.patch(
                    "/nerve/v2/workloads",
                    data=m_enc,
                    content_type=m_enc.content_type,
                    accepted_status=accepted_status,
                )
                if resp.status_code == requests.codes.forbidden:
                    self.owner.ms.login()
                    accepted_status = [requests.codes.ok]
                    continue
                break
        else:
            self._log.debug("Patching workload with APIv2")
            self.owner.ms.patch(
                f"/nerve/v2/workloads/{workload_id}",
                json=container_version,
                accepted_status=[requests.codes.ok],
            )

    def mod_env_var(self, env_name: str, env_value: str) -> None:
        """Modify the environment variable of a container.

        Parameters
        ----------
        env_name : str
            Name of the environment variable.
        env_value : str
            Value of the environment variable.
            If set to None, the variable will be removed from the configuration.
        """
        cont_version = self.get_container()
        if self._get_workload_type() == "docker-compose":
            msg = "Docker-compose workload environment variables can only be modified using a new compose file, try using set_compose_content(...)"
            raise RuntimeError(
                msg,
            )

        environment_vars = deepcopy(
            cont_version["versions"][0]["workloadProperties"].get("environment_variables", []),
        )

        for idx, environment in enumerate(environment_vars):
            if environment["env_variable"] == env_name:
                environment_vars.pop(idx)
                break

        if env_value is not None:
            if type(env_value) is bool:
                env_value = str(env_value).lower()
            self._log.info("Modified environment variable %s to %s", env_name, env_value)
            environment_vars.append({"env_variable": env_name, "container_value": env_value})
        else:
            self._log.info("Removed environment variable %s", env_name)
        cont_version["versions"][0]["workloadProperties"]["environment_variables"] = environment_vars
        self.mod_container(cont_version)

    def get_compose_content(self) -> dict:
        """Read compose file of the workload.

        Returns
        -------
        dict
            compose file as dict object.
        """
        self._get_workload_type("docker-compose")  # check if the workload type is a docker-compose workload
        workload_id, version_id = self._get_ids()
        file_id = self.get_compose_workload_file("compose")["_id"]

        return yaml.load(
            self.owner.ms.get(
                f"/nerve/v3/workloads/compose/{workload_id}/versions/{version_id}/files/{file_id}",
                accepted_status=[requests.codes.ok],
            ).text,
            yaml.SafeLoader,
        )

    def set_compose_image(self, image_path: str, patch_version=True) -> None:
        """Upload an compose image.

        Parameters
        ----------
        image_path : str
            path to image tar file.
        patch_version : bool
            patch existing file even if it is already deployed
        """
        self._get_workload_type("docker-compose")  # check if the workload type is a docker-compose workload
        workload_id, version_id = self._get_ids()

        repo_tags = []
        with tarfile.open(image_path, "r") as tar_file:  # noqa: PLR1702
            for member in tar_file.getmembers():
                if member.name == "manifest.json":
                    manifest = json.load(tar_file.extractfile(member))
                    repo_tags = manifest[-1].get("RepoTags", ["None"])
                    break

                if member.name.endswith(".tar.gz"):
                    with tarfile.open(fileobj=tar_file.extractfile(member), mode="r:gz") as file_inside:
                        for json_file in file_inside.getmembers():
                            if json_file.name == "manifest.json":
                                manifest = json.load(file_inside.extractfile(json_file))
                                repo_tags = manifest[-1].get("RepoTags", ["None"])
                                break

        try:
            file = self.get_compose_workload_file("docker-image", repo_tags[-1])
            if not patch_version:
                self._log.info(
                    "File with RepoTag %s already exists, skipping patching the file",
                    file.get("source"),
                )
                return
            file_id = file["_id"]
            self.owner.ms._log.info("Patching image file with source %s", file.get("source"))
        except ValueError:
            file_id = ""
            self._log.info("Uploading Image with RepoTag: %s", repo_tags[-1])

        open_files = []
        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        connect_error_count = 0
        while True:
            bin_file = open(image_path, "rb")
            open_files.append(bin_file)
            m_enc = MultipartEncoder({
                "type": "docker-image",
                "origin": "upload",
                "source": f"file;{repo_tags[-1]}",
                "file": (os.path.split(image_path)[-1], bin_file, "form-data"),
            })

            try:
                if file_id:
                    response = self.owner.ms.patch(
                        f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/files/{file_id}",
                        accepted_status=accepted_status,
                        data=m_enc,
                        content_type=m_enc.content_type,
                        timeout=(7.5, 30000),
                    )
                else:
                    response = self.owner.ms.post(
                        f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/files",
                        accepted_status=accepted_status,
                        data=m_enc,
                        content_type=m_enc.content_type,
                        timeout=(7.5, 30000),
                    )
            except requests.exceptions.ConnectionError:
                if connect_error_count > 1:
                    raise
                connect_error_count += 1
                self.owner.ms.login()
                accepted_status = [requests.codes.ok]
                continue

            if response.status_code == requests.codes.forbidden:
                self.owner.ms.login()
                accepted_status = [requests.codes.ok]
                continue
            break

        for bin_file in open_files:
            bin_file.close()

    def set_compose_repo(self, repo: str, user: str = "", password: str = "", type="docker-compose") -> None:
        """Set a compose repository.

        Parameters
        ----------
        repo : str
            repository URL.
        user : str, optional
            username for authentification on repo. The default is "".
        password : str, optional
            password for authentification on repo. The default is "".
        """
        if type == "docker-compose":
            workload_id, version_id = self._get_ids()
            try:
                file_id = self.get_compose_workload_file("docker-image", repo)["_id"]
            except ValueError:
                file_id = ""
        elif type == "docker":
            workload_id, version_id = self._get_ids(api_version=3)
            file_id = ""

        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        while True:
            m_enc = MultipartEncoder({
                "type": "docker-image",
                "origin": "docker-repo",
                "source": repo,
                **({"username": user} if user else {}),
                **({"password": password} if password else {}),
            })
            if file_id:
                self.owner.ms._log.info("Patching compose docker-repo with name %s", repo)
                resp = self.owner.ms.patch(
                    f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/files/{file_id}",
                    accepted_status=accepted_status,
                    data=m_enc,
                    content_type=m_enc.content_type,
                )
            else:
                if type == "docker":
                    m_enc = MultipartEncoder({
                        "type": "docker-image",
                        "origin": "docker-repo",
                        "source": repo,
                    })
                self._log.info("Setting Registry docker repo for %s", repo)
                m_enc.type = "compose"
                m_enc.origin = "upload"
                resp = self.owner.ms.post(
                    f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/files",
                    accepted_status=accepted_status,
                    data=m_enc,
                    content_type=m_enc.content_type,
                )
            if resp.status_code == requests.codes.forbidden:
                self.owner.ms.login()
                accepted_status = [requests.codes.ok]
                continue
            break

    def get_compose_deployable_state(self, registry_download_timeout: int = 300) -> bool:
        """Check deployable state.

        Wait for compose repo workloads to be loaded. Afterwards the workload is deployable.

        Parameters
        ----------
        registry_download_timeout : int, optional
            Maximal time the command should wait for the deployable state. The default is 300.

        Returns
        -------
        bool
            If True, the workload is deployable.
        """
        self._get_workload_type("docker-compose")  # check if the workload type is a docker-compose workload
        workload_id = self._get_workload_id()
        time_start = time.time()
        while time.time() - time_start < registry_download_timeout:
            response = self.owner.ms.get(
                url=f"/nerve/v3/workloads/{workload_id}/versions",
                accepted_status=[requests.codes.ok],
            ).json()
            if self.version:
                workload_info = next(
                    wrkld_info for wrkld_info in response["data"] if wrkld_info.get("name") == self.version
                )
            else:
                workload_info = response["data"][-1]
            if workload_info["isDeployable"]:
                self._log.info("Docker compose workload is deployable")
                return True
            self._log.info(
                "%3d/%3d Compose Registry workload status: %s",
                int(time.time() - time_start),
                registry_download_timeout,
                workload_info["summarizedFileStatuses"],
            )
            if (
                workload_info["summarizedFileStatuses"]["downloading"] == 0
                and workload_info["summarizedFileStatuses"]["pending"] == 0
            ):
                break

            time.sleep(10)

        self._log.warning("Docker compose workload is NOT deployable")
        return False

    def set_compose_content(
        self,
        content: dict,
        file_name: str = "compose-file.yaml",
        patch_version=True,
    ) -> None:
        """Set compose configuration file.

        Parameters
        ----------
        content : dict
            reference to node handles (general_utils.NodeHandle).
        file_name : str, optional
            filename of the compose file. Defaults to "compose-file.yaml"
        patch_version : bool, optional
            Patch existing compose file, even if it already is available
        """
        self._get_workload_type("docker-compose")  # check if the workload type is a docker-compose workload
        workload_id, version_id = self._get_ids()

        yml_file = yaml.dump(content, indent=4, default_flow_style=False, sort_keys=False)

        try:
            file = self.get_compose_workload_file("compose")
            if not patch_version:
                self._log.info("Compose file already exists, skipping patching the file")
                return
            file_id = file["_id"]
            self._log.info("Patching compose file with name %s", file.get("originalName"))
        except ValueError:
            file_id = ""
            self._log.info("Creating compose file")

        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        while True:
            m_enc = MultipartEncoder({
                "type": "compose",
                "origin": "upload",
                "source": "file",
                "file": (file_name, yml_file, "form-data"),
            })
            if file_id:
                resp = self.owner.ms.patch(
                    f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/files/{file_id}",
                    accepted_status=accepted_status,
                    data=m_enc,
                    content_type=m_enc.content_type,
                )
            else:
                resp = self.owner.ms.post(
                    f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/files",
                    accepted_status=accepted_status,
                    data=m_enc,
                    content_type=m_enc.content_type,
                )

            if resp.status_code == requests.codes.forbidden:
                self.owner.ms.login()
                accepted_status = [requests.codes.ok]
                continue
            break
        self._log.debug("Compose file uploaded")

    def deploy(
        self,
        duts: list[type],
        deploy_name: Optional[str] = None,
        overwrite_existing: bool = True,
        api_version=2,
    ) -> dict:
        """Deploy of Docker workload.

        Parameters
        ----------
        duts : list[type]
            dut_handles of a list of multiple DUT's from 'general_utils.NodeHandle'
        deploy_name : str, optional
            Name of deployment (deploy log)
        overwrite_existing : bool, optional
            If set, an existing workload with the same name will be overwritten. The default is True.

        Returns
        -------
        dict
            dict of the MS API deploy command. "operation_name" contains the actual deploy_name
        """
        workload_id, version_id = self._get_ids(api_version=api_version)
        exclude_duts = []
        if not overwrite_existing:
            for dut in duts:
                deployed_versions = self.owner.ms.get(
                    f"/nerve/workload/node/{dut.serial_number}/devices",
                    accepted_status=[requests.codes.ok],
                    timeout=(7.5, 10),
                ).json()
                for deployed_wl in deployed_versions:
                    if (
                        deployed_wl.get("workloadId") == workload_id
                        and deployed_wl.get("versionId") == version_id
                    ):
                        self._log.info("Workload version is already deployed on %s", dut.serial_number)
                        exclude_duts.append(dut)

        duts_deploy = []
        for dut in duts:
            if dut not in exclude_duts:
                duts_deploy.append(dut)

        if deploy_name is None:
            if self.version:
                deploy_name = f"{self.workload_name}-{self.version}"
            elif self.release_version:
                deploy_name = f"{self.workload_name}-{self.release_version}"
            else:
                deploy_name = f"{self.workload_name}-latest"
        payload = {
            "deployName": deploy_name[:35],
            "dryRun": False,
            "nodes": [dut.serial_number for dut in duts_deploy],
            "retryTimes": 3,
            "versionId": version_id,
            "workloadId": workload_id,
        }
        if duts_deploy != []:
            response = self.owner.ms.post(
                url="/bom/nerve/workload/deploy",
                json=payload,
                accepted_status=[requests.codes.ok],
            )
            self._log.info("Workload deploy (%s) triggered!", response.json().get("operation_name"))
            return response.json()
        return {}

    def deploy_full(
        self,
        duts: list[type],
        deploy_name: Optional[str] = None,
        deploy_timeout: int = 400,
        check_interval: int = 120,
        overwrite_existing: bool = True,
        retry: bool = False,
        api_version=2,
    ) -> str:
        """
        Deploy a workload and wait for finished status.

        Parameters
        ----------
        duts : list[type]
            reference to node handles (general_utils.NodeHandle).
        deploy_name : str, optional
            Name of deployment (deploy log). The default is None.
        deploy_timeout : int, optional
            Maximal time to wait for the deployment to finish. The default is 400.
        check_interval : int, optional
            Interval of checking the deployment state. The default is 30.
        overwrite_existing : bool, optional
            If set, an existing workload with the same name will be overwritten. The default is True.
        retry : bool, optional
            If set, the command execution will be executed again in case of an error. The default is True.

        Returns
        -------
        str
            deployment name.
        """
        deploy_name_new = self.deploy(duts, deploy_name, overwrite_existing, api_version).get(
            "operation_name", False
        )
        if deploy_name_new is False:
            self._log.info("Workload was not deployed, will not check deploy log")
            return {}
        dpl_status = self.owner.check_for_deployment_state(
            deploy_name_new,
            "isSuccess",
            timeout=deploy_timeout,
            check_interval=check_interval,
        )
        if dpl_status.get("isSuccess") is False:
            if retry:
                self.owner.ms._log.warning("Deployment did not finish, retry to deploy workload")
                time.sleep(10)
                return self.deploy_full(
                    duts,
                    deploy_name,
                    deploy_timeout,
                    api_version,
                    retry=False,
                )
            msg = f"Workload deploy ({deploy_name_new}) could not be finished"
            raise WorkloadDeployError(msg)
        self._log.info(
            "Workload deploy (%s) finished",
            deploy_name_new,
        )
        return deploy_name_new

    # Obsolete function call
    def add_remote_screen(
        self,
        screen_name: str,
        port_number: int,
        username: str = "",
        password: str = "",
        private_key: str = "",
        connection: str = "RDP",
        service_name: str = "",
    ) -> list[dict]:
        """OBSOLETE!!!  Add remote screen to workload.

        Parameters
        ----------
        screen_name: str
            Name for remote screen on workload.
        port_number: int
            Port on the node.
        username: str
            (only for connection SSH/RDPUsername for the remote screen.
        password: str
            Password for the remote screen.
        private_key: str
            when connection SSH is defined a private key can be specified instead of username/password.
        connection: str
            Specify the type of connection either VNC, SSH or RDP.
        service_name: str
            for docker-compose-workloads, service to connect to


        Returns
        -------
        list[dict]
            List of dictionary containing the parameters of the version section,
            with the new remote screen connection.
        """
        _, version_id = self._get_ids()
        data = {
            "connection": {
                "type": "SCREEN",
                "name": screen_name,
                "connection": connection,
                "numberOfConnections": 1,
                "acknowledgment": "No",
                "port": port_number,
                "autoretry": 1,
                "password": password,
                "cursor": "",
                "swapRedBlue": False,
                "readOnly": False,
            },
        }
        if connection == "RDP":
            data["connection"]["securityMode"] = ""
            data["connection"]["username"] = username
            data["connection"]["ignoreServerCertificate"] = False

        if connection == "SSH":
            data["connection"]["privateKey"] = private_key
            data["connection"]["username"] = username

        if service_name:
            data["connection"]["serviceName"] = service_name

        return self.owner.ms.post(
            f"/nerve/remoteConnections/{version_id}",
            json=data,
            accepted_status=[requests.codes.ok],
        ).json()

    def export_remote_connection(self, yaml_file_path=""):
        """Export remote connection configurations to file.

        The exported data will be safed in the provided yaml file path.
        """
        workload_id, version_id = self._get_ids()
        rc_config = self.owner.ms.get(
            f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/export-remote-connections",
            accepted_status=[requests.codes.ok],
        )

        if yaml_file_path:
            with open(yaml_file_path, "wb") as file:
                file.write(rc_config.content)
        return yaml.safe_load(rc_config.content)

    def import_remote_connection(self, yaml_file_path):
        """Import remote connection configurations to file.

        The data will be read from the provided yaml file path.
        """
        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        while True:
            import_file = [
                (
                    "file",
                    (
                        os.path.basename(yaml_file_path),
                        open(yaml_file_path, "rb"),
                        "application/octet-stream",
                    ),
                ),
            ]
            m_enc = MultipartEncoder(import_file)

            workload_id, version_id = self._get_ids()
            resp = self.owner.ms.put(
                f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/import-remote-connections",
                content_type=m_enc.content_type,
                data=m_enc,
                accepted_status=accepted_status,
            )
            if resp.status_code == requests.codes.forbidden:
                self.owner.ms.login()
                accepted_status = [requests.codes.ok]
                continue
            break

        return resp.json()

    def create_compose_version(self, payload_version: dict, patch_version: bool = False):
        """Create or update a compose-version.

        Parameters
        ----------
        payload_version : dict
            workload description file, generated with Workloads.gen_workload_configuration(...).
            only the version section shall be passed here. e.g. wl_config['version'][0]
        patch_version : bool, optional
            update workload version with new paramters.
            If set to False a version will be created, or an already existing version
            with the same name will be left unchanged.
        """
        payload2 = deepcopy(payload_version)

        workload_id = self._get_workload_id()
        version_id = ""
        if patch_version:
            if "_id" not in payload2:
                with contextlib.suppress(ValueError):
                    _, version_id = self._get_ids()
            else:
                version_id = payload2["_id"]
                del payload2["_id"]

        if version_id:
            self._log.info("Patching an exisiting version")
            response = self.owner.ms.patch(
                f"/nerve/v3/workloads/{workload_id}/versions/{version_id}",
                json=payload2,
                accepted_status=[requests.codes.ok],
            )
        else:
            self._log.info("Creating a new version")
            response = self.owner.ms.post(
                f"/nerve/v3/workloads/{workload_id}/versions",
                json=payload2,
                accepted_status=[requests.codes.ok, requests.codes.conflict],
            )

        if response.status_code == requests.codes.conflict:
            self._log.warning(
                "Workload with same name already exists. Assuming the workload was already deployed before",
            )

    def disable_workload(self):
        """Disables a workload."""
        if self._get_workload_type() == "docker-compose":
            payload = {"disabled": True}
            self.owner.ms.patch(
                f"/nerve/v3/workloads/{self._get_workload_id()}",
                json=payload,
                accepted_status=[requests.codes.ok],
            ).json()
            self._log.info("Disabled Workload")
        else:
            payload = {
                "name": self.workload_name,
                "type": self._get_workload_type(),
                "_id": self._get_workload_id(),
                "description": "",
                "versions": [],
                "disabled": True,
            }
            self.owner.ms.patch(
                f"/nerve/workload/disable/{self._get_workload_id()}",
                json=payload,
                accepted_status=[requests.codes.ok],
            ).json()
            self._log.info("Disabled Workload")

    def get_compose_workload_file(self, file_type: str = "docker-image", file_source: str = "") -> dict:
        """Read workload file information.

        Parameters
        ----------
        file_type : str, optional
            can either searuch for docker-image or compose file
        file_source : str, optional:
            if docker-image is selected, the file-source must match the 'source' of the repo
        """
        workload_id, version_id = self._get_ids()
        files = self.owner.ms.get(
            f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/files",
            accepted_status=[requests.codes.ok],
        ).json()

        for file in files["files"]:
            if file.get("type") == file_type:
                if file_type == "compose":
                    return file
                if file_type == "docker-image" and os.path.basename(file.get("source")) == os.path.basename(
                    file_source,
                ):
                    return file

        msg = f"File not found, could not find {file_type}-{file_source}"
        raise ValueError(msg)

    def delete_compose_workload_file(self, file_type: str = "docker-image", file_name: str = ""):
        """Delete a compose file.

        Parameters
        ----------
        file_type : str, optional
            can either searuch for docker-image or compose file
        file_source : str, optional:
            if docker-image is selected, the file-source must match the 'source' of the repo
        """
        workload_id, version_id = self._get_ids()
        file = self.get_compose_workload_file(file_type, file_name)
        return self.owner.ms.delete(
            f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/files/{file['_id']}",
        )

    def delete_workload_version(self) -> dict:
        """Delete workload version only."""
        workload_id, version_id = self._get_ids()
        if self._get_workload_type() == "docker-compose":
            self.owner.ms.delete(f"/nerve/v3/workloads/{workload_id}/versions/{version_id}")
        else:
            self.owner.ms.delete(f"/nerve/v2/workloads/{workload_id}/versions/{version_id}")
        self._log.info("Workload version removed")

    def delete_workload(self) -> dict:
        """Delete workload."""
        workload_id = self._get_workload_id()
        self.owner.ms.delete(f"/nerve/v3/workloads/{workload_id}")
        self._log.info("Workload removed")

    def define_all_compose_files(self, payload: list[str] = []):
        """Define files used for Docker Compose.

        Parameters
        ----------
        payload: list[str]
            list of files to be defined
        """
        payload2 = {"files": payload}
        workload_id, version_id = self._get_ids()
        self.owner.ms.post(
            f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/define-all-files",
            json=payload2,
            accepted_status=[requests.codes.ok],
        )
        self._log.info("All files are correctly defined!")

    def export_workload_version(self):
        """Export workload version."""
        workload_id, version_id = self._get_ids()
        if self._get_workload_type() == "docker-compose":
            self.owner.ms.get(
                f"/nerve/v3/workloads/{workload_id}/versions/{version_id}/export",
                accepted_status=[requests.codes.ok],
                timeout=60,
            )
            self._log.info("Version export started!")
        else:
            self.owner.ms.get(
                f"/nerve/v2/workload/{workload_id}/{version_id}",
                accepted_status=[requests.codes.ok],
            )
            self._log.info("Version export started!")


class InternalRegistry:
    """Handle to internal registry of a MS.

    Parameters
    ----------
    owner : type
        handle to manage_workloads.Workloads object.
    workload_name : str
        selected workload name.
    version : str, optional
        selected workload version. If empty, the last version will be selected. The default is "".
    release_version : str, optional
        selected release version. If empty, the last version will be selected. The default is "".
    """

    def __init__(self, ms_handle: type):
        self.ms = ms_handle

    def get_registry_images(self, last: str = "", limit: int = 0):
        """Get registry images.

        Parameters
        ----------
        last : str, optional
            The starting point for fetching registry images. Default is "".
        limit : int, optional
            The maximum number of images to retrieve. Default is 0.

        Returns
        -------
        dict
            MS API response containing registry images.
        """
        payload = {}
        if last:
            payload["last"] = last
        if limit > 0:
            payload["limit"] = limit

        return self.ms.post(
            "nerve/registry/images",
            accepted_status=[requests.codes.ok],
            json=payload,
        ).json()

    def get_image_tags(self, image: str):
        """Get image tags.

        Parameters
        ----------
        image : str
            image name.

        Returns
        -------
        dict
            MS API response containing image tags.
        """
        payload = {"image": image}
        return self.ms.post(
            "nerve/registry/image-tags",
            accepted_status=[requests.codes.ok],
            json=payload,
        ).json()

    def check_image_status(self, images: list[str] = []):
        """Check image status.

        Parameters
        ----------
        images : list[str]
            image name(s).

        Returns
        -------
        dict
            MS API response containing image status.
        """
        payload = {"images": images}
        return self.ms.post(
            "nerve/registry/check-images-status",
            accepted_status=[requests.codes.ok],
            json=payload,
        ).json()

    def delete_image_tag(self, image: str, tag: str):
        """Delete image tag.

        Parameters
        ----------
        image : str
            image name.
        tag : str
            tag name.
        """
        payload = {"image": image, "tag": tag}
        return self.ms.post(
            "nerve/registry/delete-image-tag",
            accepted_status=[requests.codes.ok],
            json=payload,
        ).json()


def remove_unused_images_ms(self, dut_serial: type):
    """Remove unused images from node.

    Parameters
    ----------
    dut : type
        reference to node handles (general_utils.NodeHandle).
    """
    return self.ms.delete(
        f"nerve/v2/node/{dut_serial}/docker-resources/images/unused",
        accepted_status=[requests.codes.no_content],
    )


class DockerVolumes:
    """Handle to Docker volumes on node from MS.

    Parameters
    ----------
    ms_handle : type
        handle to manage_workloads.Workloads object.
    """

    def __init__(self, ms_handle: type):
        self.ms = ms_handle

    def get_volumes(self, dut_serial: type):
        """Remove unused images from node.

        Parameters
        ----------
        dut_serial : type
            reference to node serial number.
        """
        return self.ms.get(
            f"nerve/v2/node/{dut_serial}/docker-resources/volumes",
            accepted_status=[requests.codes.ok],
        )

    def delete_volume(self, dut_serial: type, volume_name: str):
        """Delete docker volume.

        Parameters
        ----------
        dut_serial: type
            reference to node serial number.
        volume_name: str
            docker volume name.
        """
        return self.ms.delete(
            f"nerve/v2/node/{dut_serial}/docker-resources/volumes/{volume_name}",
            accepted_status=[requests.codes.no_content],
        )

    # Delete all volumes on MS
    def delete_all_volumes(self, dut_serial: str):
        """Delete all docker volumes on a node."""
        # Get a list of all volumes
        response = self.get_volumes(dut_serial)

        if response.status_code != requests.codes.ok:
            raise RuntimeError(f"Failed to fetch volumes: {response.status_code} - {response.text}")

        data = response.json()

        # Check if the response is in the expected format
        if "volumes" not in data or not isinstance(data["volumes"], list):
            raise RuntimeError(f"Unexpected response format: {data}")

        # List of volume names
        volumes = [volume["name"] for volume in data["volumes"]]

        # Delete all volumes from the list
        for volume in volumes:
            print(f"Deleting volume: {volume}")
            self.delete_volume(dut_serial, volume)

    # Import volume data
    def import_volume_data_ms(self, dut_serial, volume_name, file, import_timeout=30):
        """Import data to a volume.

        Parameters
        ----------
        volume_name : str
            Name of the volume.
        file : str
            Path to the file to be imported.
        """
        m_enc = MultipartEncoder({"file": (os.path.basename(file), open(file, "rb"), "form-data")})

        self.ms.login()
        sessionid = self.ms._add_header["sessionid"]

        headers = {
            "Connection": "close",
            "Content-Type": m_enc.content_type,
            "sessionId": sessionid,
        }

        return self.ms.post(
            url=f"/nerve/v2/node/{dut_serial}/docker-resources/volumes/{volume_name}/import",
            headers=headers,  # Add headers here
            data=m_enc,
            accepted_status=[requests.codes.ok],
            timeout=(30, import_timeout),
        )

    # Export volume data
    def export_volume_data_ms(self, dut_serial, volume_name, export_timeout=30):
        """Export data from a volume.

        Parameters
        ----------
        dut_serial : type
            reference to node serial number.
        volume_name : str
            Name of the volume.
        export_timeout : int, optional
            Timeout for the export operation. The default is 30 seconds.
        """
        self.ms.login()
        sessionid = self.ms._add_header["sessionid"]

        headers = {
            "Connection": "keep-alive",
            "sessionId": sessionid,
        }

        return self.ms.post(
            url=f"/nerve/v2/node/{dut_serial}/docker-resources/volumes/{volume_name}/export",
            headers=headers,  # Add headers here
            accepted_status=[requests.codes.no_content],
            timeout=(30, export_timeout),
        )

    # Check export status
    def check_export_status(self, dut_serial, volume_name, retry_timeout=60):
        """Check the status of the export operation.

        Parameters
        ----------
        dut_serial : type
            reference to node serial number.
        volume_name : str
            Name of the volume.
        """
        start_time = time.time()

        while time.time() - start_time < retry_timeout:
            response = self.get_volumes(dut_serial).json()

            for volume in response["volumes"]:
                if volume["name"] != "compose_ms_registry_test":
                    continue
                for info in volume["backupInfo"]:
                    if info["action"] != "export":
                        continue
                    if info["status"] == "COMPLETED":
                        return info["backupName"]

            time.sleep(10)  # wait 10 seconds before retrying

        # If timeout is reached without completion
        raise TimeoutError(
            f"Export did not complete within {retry_timeout} seconds for volume '{volume_name}'."
        )
