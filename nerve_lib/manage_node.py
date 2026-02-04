# Copyright (C) 2023 TTTech Computertechnik AG. All rights reserved
# Schoenbrunnerstrasse 7, A--1040 Wien, Austria. office@tttech.com
#
# ++
# Name
#    manage_node.py
#
# Purpose
#    Handle nodes from MS (MsNode)
#
# Revision Dates
#    15-Nov-2023 (koza) Creation.
# --

"""Manage Node related operations from MS.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSNode
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     nodes = MSNode(ms_handle)
    >>>     nodes.get_nodes_by_name()
    <dict: node list from MS>
"""

import json
import logging
import os
import time
import uuid
from copy import deepcopy
from datetime import datetime
from datetime import timezone
from typing import Optional

import requests
import yaml
from requests_toolbelt import MultipartEncoder


class LocalNode:  # noqa: PLR0904
    """Node related functions from LocalUI."""

    def __init__(self, node_handle: type):
        self.node = node_handle
        self._log = logging.getLogger("NodeLocalUi")
        self.__node_version = None

    @property
    def version(self):
        """Read node version."""
        if self.__node_version is None:
            version_json = self.node.get("/api/version").json()
            if "version" in version_json:
                self.__node_version = version_json["version"]  # version < 2.9.0
            else:
                self.__node_version = version_json.get("versionName")
        return self.__node_version

    def version_smaller_than(self, version: str) -> bool:
        """Check if the node version is smaller than the provided version.

        Parameters
        ----------
        version : str
            version to be checked.

        Returns
        -------
        bool
            True if the MS version is smaller than the provided version.
        """
        if not self.version:
            self._log.warning("Could not read node version, assuming latest")
            return False
        current_version = self.version.split("-", maxsplit=1)[0].split(".")
        comp_version = version.split("-", maxsplit=1)[0].split(".")

        if len(current_version) != 3:  # noqa: PLR2004
            return False  # e.g integration, master
        if len(comp_version) != 3:  # noqa: PLR2004
            return True  # e.g integration, master

        for i in range(3):
            if int(current_version[i]) < int(comp_version[i]):
                return True
            if int(current_version[i]) > int(comp_version[i]):
                return False
        return False

    def set_proxy(self, enabled, http_proxy, https_proxy, no_proxy="", user="", password=""):
        """Manage Proxy settings on a node."""
        payload = {
            "enabled": enabled,
            "http_proxy": http_proxy,
            "https_proxy": https_proxy,
            "no_proxy": no_proxy,
            "username": user,
            "password": password,
        }

        self.node.post(
            "/api/proxy-settings",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.no_content],
        )

    def get_backup_list(self):
        """Read backup list for node."""
        return self.node.get("/api/repositories", timeout=(7.5, 15)).json()

    def set_vm_backup(self, nfs_mountpoint: str, mount_options: str = "rw,nolock"):
        """Set or disable vm-backup."""
        backup_list = self.get_backup_list()["repositories"]
        payload = {
            "path": nfs_mountpoint,
            "user": "",
            "password": "",
            "id": "",
            "protocol": "nfs",
            "type": "vmBackups",
            "options": "",
            "isMounted": True,
        }

        if nfs_mountpoint:
            if backup_list:
                return self.node.put(f"/api/repositories/{backup_list[-1]['id']}", json=payload)
            return self.node.post("/api/repositories", json=payload)

        return self.node.delete(f"/api/repositories/{backup_list[-1]['id']}")

    def set_configuration(self, ms_url: str, node_name=None):
        """
        Set onboarding configuration to connect to a management system.

        Args:
        ms_url (str): The URL of the management system.
        node_name (str): The name of the node. Required for uki nerve-node devices.
        """
        payload = {
            "cloudUrl": ms_url,
            "serialNumber": self.node.serial_number,
            "protocol": "wss",
            "timezone": {"name": "Etc/UTC"},
        }
        if node_name:
            payload["nodeName"] = node_name
        self.node.post("/api/setup/configurations", json=payload, accepted_status=[requests.codes.ok])

    def auth_ms_on_node(self, ms_url: str, username: str, password: str):
        """Authenticate the node with the management system."""
        payload = {
            "cloudUrl": ms_url,
            "username": username,
            "password": password,
        }
        self.node.post("/api/auth/verify-ms-user", json=payload, accepted_status=[requests.codes.ok])

    def offboard_node_local_ui(self):
        """Offboarding node from the Local-UI."""
        payload = {"withCredentials": True}
        self.node.post("/api/system/offboard", json=payload, accepted_status=[requests.codes.accepted])

    def check_management_system_url(self, ms_url: str):
        """Check if ms_url is valid."""
        response = self.node.get(
            "/api/setup/configurations/cloud-version",
            params={"url": f"{ms_url}"},
            json={"url": f"{ms_url}"},
            accepted_status=[requests.codes.ok, requests.codes.server_error],
        )
        self._log.debug("check_management_system_url response = %s", response.json())
        return response.status_code == requests.codes.ok

    def get_secure_id(self):
        """Read the secure id of a node."""
        if self.version_smaller_than("2.10.0"):
            return (
                self.node.get("/api/setup/configurations/secureId", accepted_status=[requests.codes.ok])
                .json()
                .get("secureId")
            )
        return (
            self.node.get("/api/setup/configurations/secure-id", accepted_status=[requests.codes.ok])
            .json()
            .get("secureId")
        )

    def get_info(self):
        """Read all node info elements."""
        try:
            response = self.node.get("/api/setup/node/info", accepted_status=[requests.codes.ok])
            info = response.json()
        except requests.exceptions.JSONDecodeError as err:
            self._log.error("GET /api/setup/node/info: Invalid json: %s", response.text)
            raise err
        return info

    def get_workload_list(self):
        """Read workload list for node."""
        return self.node.get("/api/workloads").json()

    def localui_apply_workload_configuration(self, device_id: int, zip_file: str, configurations) -> type:
        """Add a workload configuration via localui.

        Parameters
        ----------
        device_id: int
            Device ID of the workload the configuration shall be applied on.
        zip_file: str
            File path to the configuration zip file.
        configurations: list of str
            Volume of the workload configurations.

        Returns
        -------
        type
            Result of the POST request.
        """
        timestamp_ms = int(time.time() * 1000)
        payload_data = {
            "user": "local@nerve.cloud",
            "timestamp": timestamp_ms,
            "configurations": configurations,
            "restartOnConfigurationUpdate": True,
        }
        m_enc = MultipartEncoder(
            fields={
                "file": (zip_file, open(zip_file, "rb"), "application/octet-stream"),
                "data": json.dumps(payload_data),
            },
        )
        return self.node.post(
            f"/api/workloads/{device_id}/apply-configuration",
            data=m_enc,
            content_type=m_enc.content_type,
            accepted_status=[requests.codes.ok, requests.codes.no_content],
            timeout=(7.5, 10),
        )

    def create_vm_backup(self, workload_name, backup_name):
        """Create a backup of a VM workload over LocalUI."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        payload = {
            "name": backup_name,
        }
        self._log.info("Triggering VM Backup of %s to %s", workload_name, backup_name)
        return self.node.post(
            f"/api/workloads/{device_id}/backups",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

    def restart_vm_backup(self, workload_name, backup_name):
        """Restart creating backup of a VM workload over LocalUI."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        payload = {
            "name": backup_name,
        }
        self._log.info("Retry Triggering VM Backup of %s to %s", workload_name, backup_name)
        return self.node.post(
            f"/api/workloads/{device_id}/backups/restart",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

    def vm_backup_status(self, workload_name, backup_name=""):
        """Get status of backup creation of a VM workload."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        response = self.node.get(
            f"/api/workloads/{device_id}/backups",
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

        if not backup_name:
            return response

        try:
            status = next(state for state in response["backups"] if state.get("name") == backup_name)
        except StopIteration:
            self._log.error(
                "Could not read backup status of %s from workload %s",
                backup_name,
                workload_name,
            )
            return {}

        self._log.info(
            "VM Backup status of %s to %s: %s",
            workload_name,
            backup_name,
            status.get("status", "UNKNOWN"),
        )
        return status

    def get_vm_backup(self, backup_name):
        """Get VM backup details from repository."""
        response = self.node.get(
            "/api/repositories/list/backups",
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

        for backup in response["list"]:
            if backup["name"] == backup_name:
                return backup
        return []

    def deploy_vm_backup(self, backup_name):
        """Deploy a VM backup."""
        payload = {"name": f"{backup_name}", "deployAsBackup": False}

        return self.node.post(
            "/api/workloads/backups/deploy",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

    def get_deploy_backup_status(self, backup_id):
        """Get the state of a deployed backup."""
        response = self.node.get(
            "/api/workloads",
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

        for status in response["workloads"]:
            if status["workloadId"] == backup_id:
                if "deviceId" in status:
                    return True
        return False

    def get_vm_snapshot(self, workload_name):
        """Get a snapshot of a VM workload."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        return self.node.get(
            f"/api/workloads/{device_id}/snapshots",
            accepted_status=[requests.codes.ok],
        ).json()

    def create_vm_snapshot(self, workload_name, snapshot_name, description=""):
        """Create a snapshot of a VM workload."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        payload = {
            "name": snapshot_name,
            "description": description,
        }
        return self.node.post(
            f"/api/workloads/{device_id}/snapshots",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        )

    def delete_vm_snapshot(self, workload_name, snapshot_name):
        """Delete a snapshot of a VM workload."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        params = {"name": snapshot_name}
        return self.node.delete(
            f"/api/workloads/{device_id}/snapshots",
            params=params,
            accepted_status=[requests.codes.ok],
        )

    def restore_vm_snapshot(self, workload_name, snapshot_name):
        """Restore a snapshot of a VM workload."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        payload = {"name": snapshot_name}
        return self.node.put(
            f"/api/workloads/{device_id}/snapshots",
            json=payload,
            accepted_status=[requests.codes.ok],
            timeout=(7.5, 10),
        )

    def create_schedule_vm_snapshot(
        self,
        workload_name,
        schedule_type,
        interval=1,
        day="Monday",
        day_time="",
        day_hours=1,
        day_minutes=1,
        vm_state="Current",
        time_zone="Europe/Belgrade",
        timezone_offset="+2",
    ):
        """Create a schedule for snapshots of a VM workload.

        schedule_type: str
            Type of schedule (Interval, Day)
        """
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        payload = {
            "type": schedule_type,
            "intervalTime": interval,
            "day": day,
            "dayTime": day_time,
            "dayHours": day_hours,
            "dayMinutes": day_minutes,
            "vmState": vm_state,
            "timeZone": time_zone,
            "timezoneOffset": timezone_offset,
        }

        return self.node.post(
            f"/api/workloads/{device_id}/snapshots/schedule",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted, requests.codes.created],
        )

    def delete_schedule_vm_snapshot(self, workload_name):
        """Delete a schedule for snapshots of a VM workload."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]

        return self.node.delete(
            f"/api/workloads/{device_id}/snapshots/schedule",
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        )

    def reboot(self):
        """Reboot the node."""
        payload = {"source": "local_ui"}
        return self.node.post(
            "/api/system/reboot",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

    def rc_setting(self, approve: int):
        """Set remote connection approval settings.

                Valid values for 'approve' are:
        0 - Approval of connection set in Management System (default)
        1 - Always allow remote connections on this node
        2 - Request approval for every remote connection made to this node.
        """
        if approve not in {0, 1, 2}:
            msg = "Invalid value for 'approve'. Valid values are 0, 1, and 2."
            raise ValueError(msg)
        payload = {"approve": approve}
        return self.node.put(
            "/api/rc-settings",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

    def resolve_remote_connection(self, connection_uid: str, connection_request_uid: str, approved: bool):
        """Approve or reject a remote connection request.

        Parameters
        ----------
        connection_uid : str
            UID of the connection.
        connection_request_uid : str
            UID of the connection request.
        approved : bool
            True to approve the connection, False to reject it.

        Returns
        -------
        dict
            Response from the API.
        """
        payload = {
            "connectionUid": connection_uid,
            "approved": approved,
            "connectionRequestUid": connection_request_uid,
        }
        return self.node.put(
            "/api/rc-requests/resolve",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.no_content],
        ).json()

    def terminate_connections(self, rc_list: list):
        """Terminate remote connections.

        Parameters
        ----------
        rc_list : list
            List of dictionaries containing connectionUid and connectionRequestUid.

        Returns
        -------
        dict
            Response from the API.
        """
        payload = {"rcList": rc_list}
        return self.node.post(
            "/api/rc-connections/terminate-connections", json=payload, accepted_status=[requests.codes.ok]
        )

    def change_password(self, username, old_password, new_password):
        """Change the password for a user."""
        payload = {
            "username": username,
            "oldPassword": old_password,
            "newPassword": new_password,
            "newPasswordConfirmation": new_password,
        }
        return self.node.post(
            "/api/users/change-password",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

    def set_local_repository(self, protocol, repo_type, path, user=None, password=None, options=""):
        """Set a local repository."""
        payload = {
            "protocol": protocol,
            "type": repo_type,
            "path": path,
        }
        if protocol == "nfs":
            payload["options"] = options
        else:
            payload["user"] = user
            payload["password"] = password
        return self.node.post(
            "/api/repositories",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        ).json()

    def codesys_download(self):
        """Download Codesys app archive."""
        return self.node.get(
            "/api/workload/codesys/download",
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        )

    def local_node_change_resource_allocation(self, workload_name, cpu: int, memory):
        """Change resource allocation for a workload."""
        wl = self.get_workload_list()["workloads"]
        for workload in wl:
            if workload_name == workload["name"]:
                device_id = workload["deviceId"]
        payload = {"cpu": cpu, "memory": memory}

        return self.node.post(
            f"/api/workloads/{device_id}/apply-resources",
            json=payload,
        )

    def set_network_configuration(
        self,
        interface,
        allocation,
        ip_address="0.0.0.0",
        netmask="0.0.0.0",
        gateway="0.0.0.0",
        domain_names=[],
    ):
        """Set network configuration of an interface.

        Parameters
        ----------
        interface : str
            Name of the interface.
        allocation : str
            Allocation of the interface. (one of dhcp, static, unconfigured)
        ip_address : str, optional
            IP address of the interface. The default is "0.0.0.0"
        netmask : str, optional
            Netmask of the interface. The default is "0.0.0.0"
        gateway : str, optional
            Gateway of the interface. The default is "0.0.0.0"
        domain_names : list, optional
            Domain names of the interface. The default is [].
        """
        return self.node.post(
            "api/setup/network/interfaces",
            json={
                "interfaces": [
                    {
                        "interface_name": interface,
                        "allocation": allocation,
                        "ip_address": ip_address,
                        "netmask": netmask,
                        "gateway": gateway,
                        "domainNames": domain_names,
                    }
                ]
            },
            accepted_status=[requests.codes.ok],
        ).json()

    def get_network_configuration(self):
        """Get network configuration of all interface."""
        return self.node.get(
            "api/setup/network/interfaces",
            accepted_status=[requests.codes.ok],
        ).json()

    def change_ssh_password(self, current_password, new_password):
        """SSH password changed."""
        payload = {
            "currentPassword": current_password,
            "newPassword": new_password,
            "newPasswordConfirmation": new_password,
        }
        return self.node.post(
            "/api/setup/node/password?type=ssh",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.accepted],
        )

    def download_audit_log(self, destination_path: str) -> dict:
        """Download current audit log file and archives created by logrotate, compressed in a zip archive."""
        response = self.node.get("/api/system/audit-logs", accepted_status=[requests.codes.ok])
        # Open the file in binary write mode and write the content
        with open(destination_path, "wb") as file:
            file.write(response.content)

        self._log.info(f"File downloaded successfully to: {destination_path}")

    def read_file(self, file_path):
        """Read the content of a file on the device."""
        return self.node.ssh.execute(f"cat {file_path}")

    def edit_file(self, file_path, content, password):
        """Write content to a file on the device."""
        command = f"echo '{password}' | sudo -S bash -c 'echo \"{content}\" > {file_path}'"
        result = self.node.ssh.execute(command)
        logging.info("Modified content of the file: %s", result)
        return result

    def set_critical_action(self, file_path, value):
        """
        Edit the critical actions file to change 'allow' to 'not allowed' or vice versa.

        Args:
            file_path (str): The path to the YAML file containing critical actions.
            value (str): The value to set ('allow' or 'not allowed').

        Returns
        -------
            str: The modified content of the YAML file as a string.
        """
        content = self.read_file(file_path)
        logging.info("Content of the file: %s", content)
        data = yaml.safe_load(content)

        # Modify the YAML content
        for action in data.get("action", {}).values():
            for source in action.get("source", {}).values():
                if value == "not allowed" and source.get("value") == "allow":
                    source["value"] = "not allowed"
                elif value == "allow" and source.get("value") == "not allowed":
                    source["value"] = "allow"

        modified_content = yaml.safe_dump(data)
        logging.info("Modified content of the file: %s", modified_content)
        return modified_content

    def get_node_configuration(self):
        """
        Get the current node configuration.

        Returns
        -------
            dict: The current node configuration.
        """
        response = self.node.get("/api/service-os-dna/current", accepted_status=[requests.codes.ok])
        with open("current_node_config.yaml", "w", encoding="utf-8") as f:
            f.write(response.text)
        return yaml.safe_load(response.text)

    def apply_node_configuration(self, config):
        """
        Apply a new node configuration by merging it with the current configuration.
        The new configuration is saved to a YAML file and sent to the node.

        Parameters
        ----------
            config : dict
                The new configuration to apply.

        Returns
        -------
            dict: The response from the node after applying the configuration.
        """
        # Get the current configuration from the node
        current_configuration = self.get_node_configuration()
        # Apply the new configuration by merging it with the current one
        target_configuration = {**current_configuration, **config}
        # Save the target configuration to a YAML file
        yaml_file_path = "target_node_config.yaml"
        with open(yaml_file_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(target_configuration, f)
        # Prepare the multipart encoder for the YAML file
        m_enc = MultipartEncoder({
            "file": (
                os.path.basename(yaml_file_path),
                open(yaml_file_path, "rb"),
                "form-data",
            )
        })
        headers = {"Content-Type": m_enc.content_type}
        # Send PUT request with the file
        response = self.node.put(
            "/api/service-os-dna/target",
            data=m_enc,
            headers=headers,
            accepted_status=[requests.codes.accepted],
        )
        return response.json()

    def node_configuration_apply_status(self):
        """
        Check the status of the node configuration application.

        Returns
        -------
            str: The status message of the node configuration application.
        """
        timeout_seconds = 60
        interval_seconds = 5
        end_time = time.time() + timeout_seconds

        while time.time() < end_time:
            response = self.node.get("/api/service-os-dna/status", accepted_status=[requests.codes.ok])
            data = response.json()
            status = data.get("status")
            message = data.get("message", "")
            if status in {"APPLIED", "MODIFIED"}:
                return message
            if status != "RECONFIGURING":
                raise RuntimeError(f"Unexpected status '{status}', apply configuration failed")
            time.sleep(interval_seconds)
        raise RuntimeError("Status is still 'RECONFIGURING' after 60 seconds, apply configuration failed")

    def get_custom_role_permissions(self):
        """
        Get list of all permissions for the custom role via /api/permissions/custom-role (GET).
        Returns: list of permission codes (strings)
        """
        resp = self.node.request("GET", "/api/permissions/custom-role", accepted_status=[200])
        data = resp.json()
        self._log.info("Full custom role permissions API response: %s", data)
        return data["permissions"]

    def set_custom_role_permissions(self, permissions, patch_success_code=202):
        """
        Set list of permissions for the custom role via /api/permissions/custom-role (PATCH).
        permissions: list of permission codes (strings) ["AUTH:LOGOUT","AUTH:VIEW", ...
        Returns: response object
        """
        payload = {"permissions": permissions}
        return self.node.request(
            "PATCH", "/api/permissions/custom-role", json=payload, accepted_status=[patch_success_code]
        )


class MSNode:
    """Node related functions from MS.

    Parameters
    ----------
    ms_handle : type
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.
    """

    def __init__(self, ms_handle: type):
        self.ms = ms_handle
        self._log = logging.getLogger("NodeMS")

        self.node_tree = _MSNodeTree(self.ms)
        self.node_update = _MSNodeUpdate(self.ms)

    def get_nodes(self, serial_number: Optional[str] = None) -> dict:
        """Read node list of MS.

        Parameters
        ----------
        serial_number : str, optional
            Return only selected node information if paramter is set and matches to a node.
            The default is None.

        Returns
        -------
        dict
            Node list informatnion from MS API.
        """
        node_list = self.ms.get("/nerve/nodes/list", accepted_status=[requests.codes.ok]).json()
        if serial_number is not None:
            filtered_nodes = [node for node in node_list if node.get("serialNumber") == serial_number]
            if filtered_nodes:
                # Return the first matching node
                return filtered_nodes[0]
            # Return empty dictionary if no matching node found
            return {}
        # Return the entire node list
        return node_list

    def get_nodes_by_name(self, node_name_filter: Optional[str] = None) -> dict:
        """Read node list of MS filtered by name of the node.

        Parameters
        ----------
        node_name_filter : str, optional
            Return all nodes, containing the defined name. The default is None.

        Returns
        -------
        dict
            Node list informatnion from MS API.

        """
        parameters = {"limit": 50, "page": 1, "order[created]": "asc"}
        if node_name_filter:
            parameters["filterBy[name]"] = node_name_filter
        nodes = {"count": 0, "data": []}
        while True:
            nodes_single_read = self.ms.get(
                "/nerve/nodes/filtered/list", params=parameters, accepted_status=[requests.codes.ok]
            ).json()
            parameters["page"] += 1
            nodes["data"] += nodes_single_read.get("data", [])
            nodes["count"] = nodes_single_read["count"]
            if len(nodes["data"]) == nodes_single_read["count"]:
                break

        return nodes

    def get_deploy_list(self, workload_id: str, version_id: str, node_name_filter: str) -> dict:
        """Get list of nodes a workload can be deployed to.

        Parameters
        ----------
        workload_id : str
            _id of the workload.
        version_id : str
            _id of the workload version.
        node_name_filter : str
            filter nodes by name, can also be empty string.

        Returns
        -------
        dict
            List of nodes the workload can be deployed to.
        """
        parameters = {"limit": 50, "page": 1, "order[created]": "asc"}
        if node_name_filter:
            parameters["filterBy[name]"] = node_name_filter
        nodes = {"count": 0, "data": []}
        while True:
            nodes_single_read = self.ms.get(
                f"/nerve/nodes/deploy/{workload_id}/{version_id}",
                params=parameters,
                accepted_status=[requests.codes.ok],
            ).json()
            parameters["page"] += 1
            nodes["data"] += nodes_single_read.get("data", [])
            nodes["count"] = nodes_single_read["count"]
            if len(nodes["data"]) == nodes_single_read["count"]:
                break
        return nodes

    def create_node(
        self,
        name: str,
        model: str,
        secure_id: str,
        serial_number: str,
        labels: list = [],
        remote_connections: list = [],
    ) -> dict:
        """Create new node on MS.

        Parameters
        ----------
        name : str
            Node Name.
        model : str
            Node model.
        secure_id : str
            secure id of the node.
        serial_number : str
            serial_number of the node.
        labels : list, optional
            list of labels. The default is [].
        remote_connections : list, optional
            remote connections to be added. The default is [].

        Returns
        -------
        dict
            API response.
        """
        payload = {
            "name": name,
            "model": model,
            "secureId": secure_id,
            "serialNumber": serial_number,
            "labels": labels,
            "remoteConnections": remote_connections,
        }
        return self.ms.post("/nerve/node", json=payload, accepted_status=[requests.codes.ok]).json()

    def get_active_remote_connections(self) -> dict:
        """Read currently active remote connections on MS.

        Returns
        -------
        dict
            list of remote connections.
        """
        if self.ms.version_smaller_than("2.10.0"):
            url = "/nerve/activeRemoteConnections"
        else:
            url = "/nerve/active-remote-connections"
        active_connections = self.ms.get(
            url,
            accepted_status=[requests.codes.ok],
        ).json()

        return active_connections.get("data", [])

    def remove_active_remote_connections(self, remote_ids: Optional[list] = None) -> type:
        """Remove established remote connections from MS.

        Parameters
        ----------
        remote_ids : list(dict)
            list of dict containing {
                "connectionUid": str,
                "connectionRequestUid": str,
            }
            if parameter is None, all active connection will be removed

        Returns
        -------
        response object from delete operation
        """
        if remote_ids is None:
            remote_ids = []
            active_connections = self.get_active_remote_connections()
            for connection in active_connections:
                remote_ids.append({
                    "connectionUid": connection["connection"]["connectionUid"],
                    "connectionRequestUid": connection["connectionRequest"]["requestUid"],
                    "serialNumber": connection["connection"]["serialNumber"],
                    "connectionName": connection["name"],
                    "type": connection["connection"]["type"],
                    "versionId": connection["connection"]["target"]["versionId"],
                    "workloadId": connection["connection"]["target"]["workloadId"],
                })

        close_list = {"rcList": remote_ids}
        if remote_ids == []:
            self._log.info("No active remote connections")
            return []
        if self.ms.version_smaller_than("2.10.0"):
            url = "/nerve/activeRemoteConnections/terminateConnections"
            return self.ms.delete(url, json=close_list)

        url = "/nerve/active-remote-connections/terminate-connections"
        return self.ms.post(url, json=close_list)

    def fetch_rtem_token_id(self, connection_uid: str, connection_request_uid: str) -> str:
        """Get RTEM seesion ID.

        API request that is fetching RTEM session ID which is generated after
        establishing remote connection (used for ACL).

        Parameters
        ----------
        connectionUid : str
            ID of remote connection on the MS
        connectionRequestUid: str
            ID of requrest for established remote connection on the MS

        Returns
        -------
        retmSessionId: str
        """
        if self.ms.version_smaller_than("2.10.0"):
            url = f"/nerve/v2/activeRemoteConnections/tunnel/{connection_uid}/{connection_request_uid}/true"
        else:
            url = f"/nerve/v2/active-remote-connections/tunnel/{connection_uid}/{connection_request_uid}/true"
        response = self.ms.get(url, accepted_status=[requests.codes.ok]).json()
        return response["rtemSessionId"]

    def Node(self, serial_number: str) -> type:
        """Create handle for selected Node.

        Parameters
        ----------
        serial_number : str
            Serial number of the connected node.

        Returns
        -------
        type
            handle to the node.
        """
        return _SelectedNode(self, serial_number)


class _SelectedNode:  # noqa: PLR0904
    """Create handle for selected Node.

    The handle will allow to control a specific node from the MS. e.g. to read it's online state
    or to establish a remote connection.

    Parameters
    ----------
    ms_node : type
        Handle to MSNode class
    serial_number : str
        Serial number of the connected node.

    Returns
    -------
    type
        handle to the node.
    """

    def __init__(self, ms_node: type, serial_number: str):
        self.node = ms_node
        self.serial_number = serial_number
        self._log = logging.getLogger(f"Node-{serial_number}")

        self.vm_snapshot = _NodeVMSnapshot(self)
        self.vm_backup = _NodeVMBackup(self)

    # %% General Functions
    def get_details(self) -> dict:
        """Read detailed node information."""
        node_id = self.node.get_nodes(self.serial_number).get("_id")
        return self.node.ms.get(
            f"/nerve/node/{node_id}",
            accepted_status=[requests.codes.ok],
            timeout=(7.5, 10),
        ).json()

    def is_online(self) -> bool:
        """Read online state."""
        details = self.get_details()
        return details.get("connectionStatus") == "online"

    def remove(self) -> type:
        """Remove a node from MS."""
        self._log.info("Removing node from MS")
        self.node.ms.delete(f"/nerve/node/{self.serial_number}")

    def remove_node_users(self) -> type:
        """Remove cashed node users from Node."""
        self._log.info("Removing users cached on Node")
        return self.node.ms.delete(f"/nerve/v2/node/{self.serial_number}/users")

    def get_list_node_users(self) -> type:
        """Get a lists of node users."""
        self._log.info("Get List of users cached on node.")
        return self.node.ms.get(f"/nerve/v2/node/{self.serial_number}/users").json()

    def reboot(self) -> dict:
        """Reboot a node using MS function."""
        result = self.node.ms.post(
            f"/nerve/node/{self.serial_number}/reboot",
            accepted_status=[requests.codes.ok],
        ).json()
        self._log.info("Rebooting Node: %s", result.get("message"))
        time.sleep(20)  # Allow the MS to detect status change
        return result

    def get_ip_address(self) -> str:
        """Read WAN IP of the node."""
        return self.node.ms.post(
            "/nerve/dataExchange/cachedData",
            json={
                "dataId": "wan_ip_address",
                "serialNumber": self.serial_number,
                "fromNodeIfCacheEmpty": True,
            },
            accepted_status=[requests.codes.ok],
        ).json()["values"]["ip_address"]

    # %% Remote Connections
    def add_remote_connection(self, connection_payload: dict) -> dict:
        """Add a remote connection to a node.

        Example:

        >>> node.add_remote_connection({
        >>>     "acknowledgment": "No",
        >>>     "hostname": "172.20.2.1",
        >>>     "localPort": "3333",
        >>>     "name": "LocalUi",
        >>>     "oldName": "",
        >>>     "port": "3333",
        >>>     "serviceName": "",
        >>>     "type": "TUNNEL",
        >>> })
        """
        node_info = self.get_details()
        all_remote_connections = node_info["remoteConnections"]

        if isinstance(connection_payload, list):
            all_remote_connections.extend(connection_payload)
        else:
            all_remote_connections.append(connection_payload)

        payload = {
            "name": node_info["name"],
            "serialNumber": self.serial_number,
            "labels": node_info["labels"],
            "model": node_info["model"],
            "nodeId": node_info["_id"],
            "remoteConnections": all_remote_connections if connection_payload is not None else [],
        }
        if self.node.ms.version_smaller_than("2.10.0"):
            payload["secureId"] = node_info["secureId"]
        return self.node.ms.patch("/nerve/node", json=payload, accepted_status=[requests.codes.ok]).json()

    def remove_remote_connection(self, connection_payload: dict) -> dict:
        """Remove a remote connection to a node.

        Example:

        >>> node.remove_remote_connection({
        >>>     "acknowledgment": "No",
        >>>     "hostname": "172.20.2.1",
        >>>     "localPort": "3333",
        >>>     "name": "LocalUi",
        >>>     "oldName": "",
        >>>     "port": "3333",
        >>>     "serviceName": "",
        >>>     "type": "TUNNEL",
        >>> })
        """
        node_info = self.get_details()
        all_remote_connections = node_info["remoteConnections"]

        if isinstance(connection_payload, list):
            # remove from list
            for connection in connection_payload:
                all_remote_connections[:] = [conn for conn in all_remote_connections if conn != connection]
        else:
            all_remote_connections[:] = [
                conn for conn in all_remote_connections if conn != connection_payload
            ]

        payload = {
            "name": node_info["name"],
            "serialNumber": self.serial_number,
            "labels": node_info["labels"],
            "model": node_info["model"],
            "nodeId": node_info["_id"],
            "remoteConnections": all_remote_connections if connection_payload is not None else [],
        }
        if self.node.ms.version_smaller_than("2.10.0"):
            payload["secureId"] = node_info["secureId"]
        return self.node.ms.patch("/nerve/node", json=payload, accepted_status=[requests.codes.ok]).json()

    def __clean_remote_connections(
        self,
        connection_list: list,
        workload_id: str = "",
        version_id: str = "",
    ) -> list:
        """Filter remote connection list returned by MS API.

        Parameters
        ----------
        connection_list : list
            original return of connection list.
        workload_id : str, optional
            Optionally add workload id (for workload related connections). The default is "".
        version_id : str, optional
            Optinally add version id (for workload releated connections). The default is "".

        Returns
        -------
        list
            modified connection list.
        """
        remote_connections = []
        remote_connection_new = {}
        for remote_connect in connection_list:
            remote_connection_new = deepcopy(remote_connect)
            remote_connection_new |= {
                "workloadId": workload_id,
                "versionId": version_id,
                "serialNumber": self.serial_number,
                "uniqueConnectionRequestNo": str(
                    uuid.uuid4(),
                ),  # Required for Release 2.7+, ignored by earlier versions
            }
            if "__v" in remote_connection_new:
                del remote_connection_new["__v"]
            if "activeConnections" in remote_connection_new:
                del remote_connection_new["activeConnections"]
            remote_connections.append(remote_connection_new)
        return remote_connections

    def get_remote_connections(
        self, connection_name: Optional[str] = None, connection_id: Optional[str] = None
    ):
        """Read device specific remote connections.

        Parameters
        ----------
        connection_name : str, optional
            if set, return URL of matching remote connection.
            If multiple connections exist with the same name, the first will be used.
            The default is None.
        connection_id : str, optional
            if set, return URL of matching remote connection. The default is None.

        Returns
        -------
        list or str
            list containing remote connections or connection URL.
        """
        details = self.get_details()
        connection_list = self.__clean_remote_connections(details.get("remoteConnections", []))

        for connection_dict in connection_list:
            if connection_dict["_id"] == connection_id:
                return self.__get_remote_connection_url(connection_dict)
            if connection_dict["name"] == connection_name:
                return self.__get_remote_connection_url(connection_dict)

        if connection_name:
            msg = f"Connection with name {connection_name} not available"
            raise AttributeError(msg)

        return connection_list

    def get_workloads_remote_connections(
        self, workload_name: Optional[str] = None, connection_name: Optional[str] = None
    ):
        """Read workload specific remote connections.

        Parameters
        ----------
        workload_name : str, optional
            if set, only remote connections of this workload are read. The default is None.
        connection_name : str, optional
            if set, return URL of matching remote connection. The default is None.

        Returns
        -------
        dict or str
            list containing workload remote connections or connection URL.

        """
        workloads = self.get_workloads(workload_name)
        if type(workloads) is dict:
            workloads = [workloads]
        remote_connection_dict = {}
        for workload in workloads:
            if workload["type"] == "docker-compose":
                wl_version = self.node.ms.get(
                    f"/nerve/v3/workloads/{workload['workloadId']}/versions/{workload['versionId']}",
                    accepted_status=[requests.codes.ok],
                ).json()
            else:
                versions = (
                    self.node.ms.get(
                        f"nerve/v2/workloads/{workload['workloadId']}",
                        accepted_status=[requests.codes.ok],
                    )
                    .json()
                    .get("versions", [])
                )
                wl_version = next(filter(lambda x: x.get("_id") == workload["versionId"], versions))

            connection_list = self.__clean_remote_connections(
                wl_version.get("remoteConnections", []),
                workload["workloadId"],
                workload["versionId"],
            )
            remote_connection_dict[workload["device_name"]] = connection_list
            for connection_dict in connection_list:
                if connection_dict["name"] == connection_name:
                    return self.__get_remote_connection_url(connection_dict)

        if connection_name:
            msg = f"Connection with name {connection_name} not available"
            raise AttributeError(msg)

        return remote_connection_dict

    def __get_remote_connection_url(self, connection_dict: dict, retry: bool = True) -> str:
        """Create URL for RTEM connection.

        Parameters
        ----------
        connection_dict : dict
            remote connection element.
        retry : bool, optional
            if true, creating URL will be executed again in case a KeyError is raised. The default is True.

        Returns
        -------
        str
            connection URL for RTEM.
        """
        con_dict_copy = deepcopy(connection_dict)
        if self.node.ms.version_smaller_than("2.10.0"):
            url = "/nerve/remoteConnections/connect"
        else:
            url = "/nerve/remote-connections/connect"
            for key in list(con_dict_copy.keys()):  # Iterate over a copy of the keys to avoid runtime issues
                if key not in {
                    "acknowledgment",
                    "connection",
                    "name",
                    "port",
                    "serialNumber",
                    "type",
                    "versionId",
                    "workloadId",
                    "uniqueConnectionRequestNo",
                    "_id",
                }:
                    del con_dict_copy[key]
        response = self.node.ms.post(url, json=con_dict_copy, accepted_status=[requests.codes.ok])
        session_id = response.request.headers["sessionid"]
        try:
            connect_url = None
            if "url" not in response.json():
                time.sleep(5)
                active_connection = self.node.get_active_remote_connections()
                for connection in active_connection:
                    if response.json()["requestUid"] == connection["connectionRequest"]["requestUid"]:
                        connect_id = connection["connection"]["_id"]
                        url = f"nerverm://{self.node.ms.ms_url}"
                        connect_url = f"{url}/{connect_id}/{response.json()['requestUid']}/{session_id}"
                        break
            else:
                connect_url = f"{response.json()['url']}/{session_id}"
        except KeyError:
            if retry:
                return self.__get_remote_connection_url(con_dict_copy, retry=False)
            msg = f"Response is unexpected, should contain key 'url'\n{response.text}"
            raise Exception(msg)
        return connect_url

    def import_remote_connections(self, yaml_file: str):
        """Import remote connections to node from .yaml file."""
        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        while True:
            m_enc = MultipartEncoder(
                fields={"file": (yaml_file, open(yaml_file, "rb"), "application/octet-stream")},
            )
            resp = self.node.ms.put(
                f"/nerve/v2/node/{self.serial_number}/import-remote-connections",
                accepted_status=accepted_status,
                data=m_enc,
                content_type=m_enc.content_type,
            )
            if resp.status_code == requests.codes.forbidden:
                self.node.ms.login()
                accepted_status = [requests.codes.ok]
                continue
            break
        return resp.json()

    def export_remote_connections(self, yaml_file=""):
        """Export remote connections from node."""
        rc_config = self.node.ms.get(
            f"/nerve/v2/node/{self.serial_number}/export-remote-connections",
            accepted_status=[requests.codes.ok],
        )

        if yaml_file:
            with open(yaml_file, "wb") as file:
                file.write(rc_config.content)
        return yaml.safe_load(rc_config.content)

    # %% Logging settings
    def get_logging_settings(self) -> dict:
        """Read logging settings of the node.

        Returns
        -------
        dict
            MS API response. e.g.

            >>> {
            >>> "dockerMonitoring": false,
            >>> "dockerLogging": false,
            >>> "systemMonitoring": false
            >>> }
        """
        return self.node.ms.get(
            f"/nerve/node/monitoringAndLoggingSettings/{self.serial_number}",
            accepted_status=[requests.codes.ok],
        ).json()

    def set_logging_settings(self, settings: dict) -> type:
        """Set new system monitoring configuration.

        Parameters
        ----------
        settings : dict
            Enabling different logging option. e.g.

            >>> {
            >>> "dockerMonitoring": false,
            >>> "dockerLogging": false,
            >>> "systemMonitoring": false
            >>> }

        Returns
        -------
        type
            response object of the post command.
        """
        return self.node.ms.post(
            f"/nerve/node/applyMonitoringAndLoggingSettings/{self.serial_number}",
            json=settings,
        )

    def set_log_levels(self, settings: dict) -> type:
        """Set new log level configuration.

        Requires "UI_NODE_LOG_LEVEL:MANAGE_LOG_LEVELS" permission.

        Parameters
        ----------
        settings : dict
            Enabling different logging option. e.g.

            >>> {
            >>>     "loggingMonitoring": {
            >>>         "supported": true,
            >>>         "dockerMonitoring": false,
            >>>         "systemMonitoring": false,
            >>>         "dockerLogging": false
            >>>     },
            >>>     "logLevels": {
            >>>         "ovdm": "info",
            >>>         "timeout": 18000000,
            >>>         "libvirt_ctl": "10",
            >>>         "codesys_ctl": "30"
            >>>         }
            >>> }

        Returns
        -------
        type
            response object of the put command.
        """
        if self.node.ms.version_smaller_than("2.10.0"):
            return self.node.ms.put(f"/nerve/v2/node/logging-monitoring/{self.serial_number}", json=settings)
        return self.node.ms.post(f"/nerve/v2/node/logging-monitoring/{self.serial_number}", json=settings)

    # %% Workload operations
    def get_workloads(self, workload_name: Optional[str] = None) -> dict:
        """Read currently deployed workloads of the node.

        Parameters
        ----------
        workload_name : str, optional
            If set, only specific workload information will be returned. The default is None

        Returns
        -------
        dict
            MS API response.
        """
        dep_workloads = self.node.ms.get(
            f"/nerve/workload/node/{self.serial_number}/devices",
            accepted_status=[requests.codes.ok],
            timeout=(7.5, 120),
        ).json()
        if workload_name is None:
            return dep_workloads

        for workload in dep_workloads:
            if workload_name == workload.get("device_name"):
                return workload
        msg = f"Workload with name {workload_name} does not exist on dut"
        raise AttributeError(msg)

    def workload_control(self, workload_name: str, command: str, remove_images=True) -> None:
        """Control the workload status.

        Parameters
        ----------
        workload_name : str
            Workload to be controlled.
        command : str
            Command can be one of START, STOP, SUSPEND, RESUME, RESTART, UNDEPLOY".
        """
        workload = self.get_workloads(workload_name)
        workload_id = workload.get("workloadId")
        version_id = workload.get("versionId")
        if len(workload_id) > 24:  # noqa: PLR2004
            workload_id = workload_id[:24]
        if len(version_id) > 24:  # noqa: PLR2004
            version_id = version_id[:24]
        payload = {
            "command": command.upper(),
            "serialNumber": self.serial_number,
            "sessionToken": self.node.ms._add_header.get("sessionid"),
            "deviceId": workload.get("id"),
            "workloadId": workload_id,
            "versionId": version_id,
        }
        if command.upper() == "UNDEPLOY":
            payload["removeImages"] = remove_images

        self._log.info(
            "Triggering Command '%s' on workload '%s'",
            command.upper(),
            workload.get("device_name"),
        )
        self.node.ms.post(url="/nerve/workload/controller", json=payload, accepted_status=[requests.codes.ok])

    def workload_status(self, workload_name: str, print_log=True) -> None:
        """Get the current the workload status.

        Parameters
        ----------
        workload_name : str
            Workload to be controlled.
        """
        workload = self.get_workloads(workload_name)
        service_list = workload.get("service_list", [])
        property_list = next(
            service.get("property_list", [])
            for service in service_list
            if service.get("name") == "VMControlService"
        )
        state_info = next(state for state in property_list if state.get("name") == "State")
        current_state = state_info["options"][state_info["value"]]
        if print_log:
            self._log.info("State of workload %s is %s", workload_name, current_state)
        return current_state

    def undeploy_workloads(
        self, workload_name: Optional[str] = None, retry: bool = True, remove_images: bool = True
    ) -> None:
        """Undeploy all deployed workloads on DUT.

        Parameters
        ----------
        workload_name: str
            if set, only specific workload will be undeployed.
        """
        try:
            dep_workloads = self.get_workloads(workload_name)
            if type(dep_workloads) is dict:
                dep_workloads = [dep_workloads]
            removal_count = 0
            for workload in dep_workloads:
                self.workload_control(workload.get("device_name"), "UNDEPLOY", remove_images=remove_images)
                removal_count += 1

            self._log.info("%s workloads are undeployed from DUT", removal_count)
        except Exception as ex_msg:
            self._log.warning(ex_msg)
            if retry:
                self._log.warning("Could not read workloads, retry in 5 seconds")
                time.sleep(5)
                self.undeploy_workloads(workload_name, retry=False)
            else:
                raise ex_msg

    def apply_workload_configuration(self, workload_name: str, zip_file: str, service_name: str = "") -> type:
        """Add a workload configuration.

        Parameters
        ----------
        workload_name : str
            Name of the workload the configuration shall be applied on.
        zip_file : str
            file-path to the configuration zip-file.
        service_name: str, optional
            If the workload is a docker-compose, specify the name of the service in addition.
        """
        workload = self.get_workloads(workload_name)
        workload_id = workload["workloadId"]
        version_id = workload["versionId"]
        device_id = workload["id"]

        node_data = self.get_workload_details(workload_name)
        update_info = node_data["values"]["configurationUpdateInfo"]
        if service_name:
            update_info = next(info for info in update_info if info["serviceName"] == service_name)
            update_volume = {"name": update_info["name"], "path": update_info["path"]}
            self._log.info("Updating volume %s", update_volume)
            data = {
                "action": "apply",
                "volume": update_volume,
                "restartOnConfigurationUpdate": str(update_info["restartOnConfigurationUpdate"]).lower(),
                "workloadId": workload_id,
                "versionId": version_id,
                "service": service_name,
            }

        else:
            self._log.info("Updating volume %s", json.dumps(update_info["configurationVolumes"][0]))
            data = {
                "action": "apply",
                "volume": update_info["configurationVolumes"][0],
                "restartOnConfigurationUpdate": str(update_info["restartOnConfigurationUpdate"]).lower(),
                "workloadId": workload_id,
                "versionId": version_id,
            }
        m_enc = MultipartEncoder({
            "data": (None, json.dumps(data), "form-data"),
            "file": (zip_file, open(zip_file, "rb"), "application/zip"),
        })

        return self.node.ms.post(
            f"/nerve/nodes/{self.serial_number}/workloads/{device_id}/configurations",
            data=m_enc,
            content_type=m_enc.content_type,
            accepted_status=[requests.codes.ok, requests.codes.no_content],
        )

    def apply_compose_configuration(
        self,
        compose_name: str,
        zip_file: str,
        service_name: str,
        volume,
    ) -> type:
        """Add a compose configuration for specific service.

        Parameters
        ----------
        compose_name : str
            Name of the docker compose the configuration shall be applied on.
        zip_file : str
            file-path to the configuration zip-file.
        service_name : str
            Name of the service the configuration shall be applied on.
        volume :
            {"name": "vol", "path": "/etc/nginx"}
        """
        workload = self.get_workloads(compose_name)
        workload_id = workload["workloadId"]
        version_id = workload["versionId"]
        device_id = workload["id"]

        data = {
            "action": "apply",
            "service": service_name,
            "volume": volume,
            "restartOnConfigurationUpdate": True,
            "workloadId": workload_id,
            "versionId": version_id,
        }
        m_enc = MultipartEncoder({
            "data": (None, json.dumps(data), "form-data"),
            "file": (zip_file, open(zip_file, "rb"), "application/zip"),
        })

        return self.node.ms.post(
            f"/nerve/nodes/{self.serial_number}/workloads/{device_id}/configurations",
            data=m_enc,
            content_type=m_enc.content_type,
            accepted_status=[requests.codes.ok, requests.codes.no_content],
        )

    def change_resources_allocation(self, workload_name: str, memory: str) -> type:
        """Change resources allocation for vm workload.

        Parameters
        ----------
        workload_name : str
            workload name to change the resource allocation on.
        memory : str
            New memory value, e.g. 800MB.
        """
        workload = self.get_workloads(workload_name)

        payload = {
            "memory": memory.upper(),
            "serialNumber": self.serial_number,
            "device_id": workload["id"],
            "workloadId": workload["workloadId"],
            "versionId": workload["versionId"],
        }
        return self.node.ms.post(
            "/nerve/workload/updateResources",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.no_content],
        )

    def get_activity_log(self, workload_name: str) -> dict:
        """Read the activity log of a workload."""
        workload = self.get_workloads(workload_name)

        parameters = {"limit": 50, "page": 1, "search": ""}
        logs = {"count": 0, "data": []}
        while True:
            logs_single_read = self.node.ms.get(
                f"/nerve/v2/node/{self.serial_number}/versions/{workload.get('versionId')}/activity-logs",
                params=parameters,
                accepted_status=[requests.codes.ok],
            ).json()
            parameters["page"] += 1
            logs["data"] += logs_single_read.get("data", [])
            logs["count"] = logs_single_read["count"]
            if len(logs["data"]) == logs_single_read["count"]:
                break
        return logs

    def download_activity_log(self, workload_name: str, destination_path: str) -> dict:
        """
        Download target configuration from node.

        File should be csv that should contains .csv file and workload name.
        """
        if workload_name:
            workload = self.get_workloads(workload_name)

            # the endpoint for specific workload
            response = self.node.ms.get(
                f"/nerve/v2/node/{self.serial_number}/versions/{workload.get('versionId')}/activity-logs/download",
                accepted_status=[requests.codes.ok],
            )
        else:
            # the endpoint for all workloads
            response = self.node.ms.get(
                f"/nerve/v2/node/{self.serial_number}/workloads/activity-logs/download",
                accepted_status=[requests.codes.ok],
            )

        # Open the file in binary write mode and write the content
        with open(destination_path, "wb") as file:
            file.write(response.content)

        self._log.info(f"File downloaded successfully to: {destination_path}")

    def get_workload_details(self, workload_name: str) -> dict:
        """Get detailed workload information.

        Parameters
        ----------
        workload_name : str
            Name of the workload the details shall be read from.
        """
        workload = self.get_workloads(workload_name)
        device_id = workload["id"]
        if self.node.ms.version_smaller_than("2.10.0"):
            url = "/nerve/dataExchange/nodeData"
        else:
            url = "/nerve/data-exchange/node-data"
        return self.node.ms.post(
            url,
            json={
                "dataId": "workload",
                "serialNumber": self.serial_number,
                "requestConfig": {"forceRequest": True, "timeout": 10000},
                "data": device_id,
            },
            accepted_status=[requests.codes.ok],
        ).json()

    def edit_node(
        self,
        serial_number: Optional[str] = None,
        name: Optional[str] = None,
        model: Optional[str] = None,
        secure_id: Optional[str] = None,
        labels: Optional[list] = None,
        remote_connections: Optional[list] = None,
    ) -> dict:
        """Edit an existing node on MS.

        Parameters
        ----------
        serial_number : str
            The serial number of the node to be edited.
        name : str, optional
            Node Name.
        model : str, optional
            Node model.
        secure_id : str, optional
            Secure id of the node.
        labels : list, optional
            List of labels. The default is [].
        remote_connections : list, optional
            Remote connections to be added. The default is [].

        Returns
        -------
        dict
            API response.
        """
        # Fetch node information
        payload = self.get_details()
        node_id = self.node.get_nodes(self.serial_number).get("_id")
        payload["nodeId"] = node_id
        if name:
            payload["name"] = name
        if model:
            payload["model"] = model
        if secure_id:
            payload["secureId"] = secure_id
        if serial_number:
            payload["serialNumber"] = serial_number
        if labels:
            payload["labels"] = labels
        else:
            payload["labels"] = []
        if remote_connections:
            payload["remoteConnections"] = remote_connections
        else:
            payload["remoteConnections"] = []

        return self.node.ms.patch("/nerve/node", json=payload, accepted_status=[requests.codes.ok]).json()

    def remove_unused_images(self):
        """Remove unused images from node.

        Parameters
        ----------
        dut : type
            reference to node handles (general_utils.NodeHandle).
        Returns
        -------
        Response object from the MS API.
        """
        return self.node.ms.delete(
            f"nerve/v2/node/{self.serial_number}/docker-resources/images/unused",
            accepted_status=[requests.codes.no_content],
        )


class _NodeVMBackup:
    """Extension for VM Backup operations on a selected node."""

    def __init__(self, owner: _SelectedNode):
        self.owner = owner

    def create(self, workload_name, backup_name):
        """Create a backup of a VM workload.

        Requires WORKLOAD:BACKUP permission.
        """
        workload = self.owner.get_workloads(workload_name)

        payload = {
            "name": backup_name,
            "workloadId": workload.get("workloadId"),
            "versionId": workload.get("versionId"),
        }
        self.owner._log.info("Triggering VM Backup of %s to %s", workload_name, backup_name)
        return self.owner.node.ms.post(
            f"/nerve/workload/node/{self.owner.serial_number}/backups/{workload['id']}",
            json=payload,
            accepted_status=[requests.codes.ok],
        ).json()

    def restart(self, workload_name, backup_name):
        """Restart creating backup of a VM workload.

        Requires WORKLOAD:BACKUP permission.
        """
        workload = self.owner.get_workloads(workload_name)

        payload = {
            "name": backup_name,
            "workloadId": workload.get("workloadId"),
            "versionId": workload.get("versionId"),
        }
        self.owner._log.info("Retry Triggering VM Backup of %s to %s", workload_name, backup_name)
        return self.owner.node.ms.post(
            f"/nerve/workload/node/{self.owner.serial_number}/backups/{workload['id']}/restart",
            json=payload,
            accepted_status=[requests.codes.ok],
        ).json()

    def status(self, workload_name, backup_name=""):
        """Get status of backup creation of a VM workload.

        Requires WORKLOAD:BACKUP permission.
        """
        workload = self.owner.get_workloads(workload_name)

        response = self.owner.node.ms.get(
            f"/nerve/workload/node/{self.owner.serial_number}/backups/{workload['id']}",
            accepted_status=[requests.codes.ok],
        ).json()

        if not backup_name:
            return response

        try:
            status = next(state for state in response if state.get("name") == backup_name)
        except StopIteration:
            self.owner._log.error(
                "Could not read backup status of %s from workload %s",
                backup_name,
                workload_name,
            )
            return {}

        self.owner._log.info(
            "VM Backup status of %s to %s: %s",
            workload_name,
            backup_name,
            status.get("status", "UNKNOWN"),
        )
        return status


class _NodeVMSnapshot:
    """Extension for VM Snapshot operations on a selected node."""

    def __init__(self, owner: _SelectedNode):
        self.owner = owner

    def create(self, workload_name, snapshot_name, description=""):
        """Create a snapshot of a VM workload.

        Requires WORKLOAD:SNAPSHOT permission.
        """
        workload = self.owner.get_workloads(workload_name)

        payload = {
            "name": snapshot_name,
            "description": description,
            "workloadId": workload.get("workloadId"),
            "versionId": workload.get("versionId"),
        }
        return self.owner.node.ms.post(
            f"/nerve/workload/node/{self.owner.serial_number}/snapshots/{workload['id']}",
            json=payload,
            accepted_status=[requests.codes.ok],
        )

    def delete(self, workload_name, snapshot_name):
        """Delete a snapshot of a VM workload.

        Requires WORKLOAD:SNAPSHOT permission.
        """
        workload = self.owner.get_workloads(workload_name)

        payload = {
            "name": snapshot_name,
            "workloadId": workload.get("workloadId"),
            "versionId": workload.get("versionId"),
        }
        return self.owner.node.ms.delete(
            f"/nerve/workload/node/{self.owner.serial_number}/snapshots/{workload['id']}",
            json=payload,
            accepted_status=[requests.codes.ok],
        )

    def restore(self, workload_name, snapshot_name):
        """Restore a snapshot of a VM workload.

        Requires WORKLOAD:SNAPSHOT permission.
        """
        workload = self.owner.get_workloads(workload_name)

        payload = {
            "name": snapshot_name,
            "workloadId": workload.get("workloadId"),
            "versionId": workload.get("versionId"),
        }
        return self.owner.node.ms.put(
            f"/nerve/workload/node/{self.owner.serial_number}/snapshots/{workload['id']}",
            json=payload,
            accepted_status=[requests.codes.ok],
        )

    def schedule_create(self, workload_name, interval_hours):
        """Restore a snapshot of a VM workload.

        Requires WORKLOAD:SNAPSHOT permission.
        """
        workload = self.owner.get_workloads(workload_name)

        payload = {
            "type": "Interval",
            "intervalTime": interval_hours,
            "day": "",
            "dayTime": "",
            "dayHours": 1,
            "dayMinutes": 1,
            "vmState": "Current",
            "timeZone": "Europe/Belgrade",
            "timezoneOffset": "+1",
            "workloadId": workload.get("workloadId"),
            "versionId": workload.get("versionId"),
        }

        return self.owner.node.ms.post(
            f"/nerve/workload/node/{self.owner.serial_number}/snapshots/schedule/{workload['id']}",
            json=payload,
            accepted_status=[requests.codes.ok],
        ).json()

    def schedule(self, workload_name, interval_hours=-1):
        """Create a schedule for snapshots of a VM workload.

        Setting interval_hours to -1 (default) disables the schedule.
        Requires WORKLOAD:SNAPSHOT permission.
        """
        workload = self.owner.get_workloads(workload_name)

        if interval_hours == -1:
            payload = {"workloadId": workload.get("workloadId"), "versionId": workload.get("versionId")}
            return self.owner.node.ms.delete(
                f"/nerve/workload/node/{self.owner.serial_number}/s/schedule/{workload['id']}",
                json=payload,
                accepted_status=[requests.codes.ok],
            )

        # Create a new schedule
        payload = {
            "type": "Interval",
            "intervalTime": interval_hours,
            "day": "",
            "dayTime": "",
            "dayHours": 1,
            "dayMinutes": 1,
            "vmState": "Current",
            "timeZone": "Europe/Belgrade",
            "timezoneOffset": "+1",
            "workloadId": workload.get("workloadId"),
            "versionId": workload.get("versionId"),
        }

        return self.owner.node.ms.post(
            f"/nerve/workload/node/{self.owner.serial_number}/snapshots/schedule/{workload['id']}",
            json=payload,
            accepted_status=[requests.codes.ok],
        ).json()

    def schedule_delete(self, workload_name):
        """Delete a snapshot schedule of a VM workload.

        Requires WORKLOAD:SNAPSHOT permission.
        """
        workload = self.owner.get_workloads(workload_name)

        payload = {
            "workloadId": workload.get("workloadId"),
            "versionId": workload.get("versionId"),
        }
        return self.owner.node.ms.delete(
            f"/nerve/workload/node/{self.owner.serial_number}/snapshots/schedule/{workload['id']}",
            json=payload,
            accepted_status=[requests.codes.ok],
        )


class _MSNodeTree:
    """Node Tree related functions."""

    def __init__(self, ms_handle: type):
        self.ms = ms_handle
        self._log = logging.getLogger("NodeTree")

    @staticmethod
    def __short_tree_items(items: list) -> list:
        """Create compact view of tree items.

        Parameters
        ----------
        items : list
            tree items as read by MS API.

        Returns
        -------
        return_items : list
            compact item containing _id, name, serialNumber, connectionStatus, currentFWVersion.
        """
        return_items = []
        for item in items:
            node_entry = {}
            if item["type"] != "node":
                node_entry = item
            for field in ["_id", "name"]:
                node_entry[field] = item[field]
            for field in ["serialNumber", "connectionStatus", "currentFWVersion"]:
                if "device" in item:
                    node_entry[field] = item["device"][field]
            return_items.append(node_entry)
        return return_items

    def get_child_type(self, item_type: str, short_items: bool = False) -> list:
        """Read all items of a defined type.

        Parameters
        ----------
        item_type : str
            one of "folder, node, unassinged, root"
        short_items : bool, optional
            if set, tree items will be listed in compact view. The default is False.
        """
        items = self.ms.get(f"/nerve/tree-node/child-type/{item_type}").json()

        return self.__short_tree_items(items) if short_items else items

    def _get_folder_by_name(self, name):
        child_type = "folder"
        if name in {"unassigned", "Root"}:
            child_type = name.lower()

        return next(folder for folder in self.get_child_type(child_type) if folder["name"] == name)

    def _get_node_by_name(self, name):
        try:
            node = next(item for item in self.get_child_type("node") if item["name"] == name)
        except StopIteration:
            try:
                node = next(item for item in self.get_child_type("unassigned") if item["name"] == name)
            except StopIteration:
                msg = f"Node '{name}' could not be found"
                raise ValueError(msg)
        return node

    def _get_tree_node(self, parent_id):
        """Read elements of a parten_id."""
        return self.ms.get(f"/nerve/tree-node/parent/{parent_id}", accepted_status=[requests.codes.ok]).json()

    def _get_tree(
        self, parent_id: Optional[str] = None, short_items: bool = True, flat: bool = False
    ) -> list:
        """Read node tree from MS.

        Parameters
        ----------
        parent_id : str, optional
            Read tree starting from this ID. The default is root element.
        short_items : bool, optional
            if set, create a compact output similar to .get_nodes(). The default is True.
        flat : bool, optional
            If flat is set, all tree elements below a parent will be listed in one layer.
            The default is True.
        """
        if parent_id is None:
            parent_id = self._get_folder_by_name("Root")["_id"]

        tree_items = self._get_tree_node(parent_id)

        return_items = self.__short_tree_items(tree_items) if short_items else tree_items

        for idx, item in enumerate(return_items):
            if item.get("type") == "folder":
                if not flat:
                    return_items[idx] = {item["name"]: self._get_tree(item["_id"], short_items, flat)}
                else:
                    return_items[idx] = None
                    return_items += self._get_tree(item["_id"], short_items, flat)
            elif item.get("type") == "unassigned":
                if not flat:
                    return_items[idx] = {item["name"]: self.get_child_type("unassigned", short_items)}
                else:
                    return_items[idx] = None
                    return_items += self.get_child_type("unassigned", short_items)

        return [item for item in return_items if item]

    def create_folder_path(self, tree_path):
        """Create a folder structure in node-tree."""
        item_id = self._get_folder_by_name("Root")["_id"]
        for folder in tree_path.split("/"):
            parent_id = item_id
            resp = self.ms.post(
                "/nerve/tree-node/mock",
                json={
                    "treeNodeData": {
                        "parentId": parent_id,
                        "name": folder,
                        "type": "folder",
                        "orderIndex": 0,
                    },
                },
                accepted_status=[requests.codes.ok, requests.codes.conflict],
            )
            if resp.status_code == requests.codes.conflict:
                self._log.debug("Folder '%s' already exists", folder)
                item_id = self._get_folder_by_name(folder)["_id"]
                continue

            item_id = resp.json()["_id"]
            self.ms.put(
                "nerve/tree-node/upsert-many",
                json={
                    "treeNodes": [
                        {
                            "parentId": parent_id,
                            "name": folder,
                            "type": "folder",
                            "orderIndex": 1,
                            "_id": item_id,
                        },
                    ],
                },
            )
            parent_id = item_id
        return item_id

    def move_node_to_folder(self, node_name, tree_path, order_index=-1):
        """Move a node to a different node-tree location.

        Parameters
        ----------
        node_name : str
            Name of the node
        tree_path : str
            Desination path e.g. test/node/path
        order_index : int
            Position to insert the node into. -1 will add it to the last index
        """
        node = self._get_node_by_name(node_name)
        destination_id = self.create_folder_path(tree_path)

        dest_folder = self._get_tree_node(destination_id)
        node["parentId"] = destination_id

        if order_index == -1 or order_index >= len(dest_folder):
            order_index = len(dest_folder)
        dest_folder.insert(order_index, node)

        for idx, node_item in enumerate(dest_folder):
            node_item["orderIndex"] = idx

        self.ms.put(
            "nerve/tree-node/upsert-many",
            json={"treeNodes": dest_folder},
        )
        return dest_folder

    def delete_folder(self, name: str):
        """Delete a folder by its name."""
        folder_id = self._get_folder_by_name(name)["_id"]

        self.ms.delete(f"/nerve/tree-node/{folder_id}")

    def edit_folder(self, name: str, name_new: str = "", order_idx: int = 0):
        """Edit the name of a folder.

        Parameters
        ----------
        name : str
            Current folder name to be modified
        name_new : str, optional
            Change the name of a folder, if left emtpy, the name will not be changed
        order_idx : int, optional
            Change the index of a folder. If left 0, the index will be unchanged
        """
        folder = self._get_folder_by_name(name)

        payload = {
            "treeNodes": [
                {
                    "_id": folder["_id"],
                    "parentId": folder.get("parentId"),
                    "name": name_new or folder["name"],
                    "type": folder["type"],
                    "orderIndex": order_idx or folder["orderIndex"],
                },
            ],
        }
        self.ms.put("/nerve/tree-node/upsert-many", json=payload)


class _MSNodeUpdate:
    def __init__(self, ms_handle: type):
        self.ms = ms_handle
        self._log = logging.getLogger("NodeUpdate")

    def get_possible_updates(self, serial_numbers: list):
        """Get dict of versions including node serial numbers that can be updated.

        Parameters
        ----------
        serial_numbers : list
            List of serial numbers to be listed. If empty, all nodes will be considered.
        """
        possible_versions = {}
        versions = self.ms.get("/nerve/update/local-node-update").json().get("nodeUpdates", [])
        for version in versions:
            details = self._get_update_version_info(version["name"])
            comp_versions = []
            for detail in details:
                comp_versions = detail["updateFrom"]
            comp_devices = self.ms.get(
                "/nerve/devices/search-compatible-devices",
                params={
                    "filterBy": json.dumps({
                        "compatibleVersions": comp_versions,
                        "connectionStatus": "online",
                    }),
                    "limit": 100,
                    "page": 1,
                },
            ).json()

            possible_versions[version["name"]] = [
                device["serialNumber"]
                for device in comp_devices["devices"]
                if device["serialNumber"] in serial_numbers or not serial_numbers
            ]
        return possible_versions

    def _get_update_version_info(self, update_version: str = ""):
        """Get update version details optional filtered by update_version."""
        return self.ms.get(
            "nerve/update/node/details-by-name", params={"versionName": update_version}
        ).json()["nodeUpdateDetails"]

    def update_nodes_to_version(self, serial_numbers: list, update_version: str = ""):
        """Update node to a specific version.

        Parameters
        ----------
        node_serial : str
            Serial number of the node.
        update_version : str
            Version to be updated to.
        """
        update_info = self._get_update_version_info(update_version)
        if not update_info:
            msg = f"Update version {update_version} not available"
            raise ValueError(msg)
        payload = {
            "devices": [serial_numbers] if isinstance(serial_numbers, str) else serial_numbers,
            "version": update_info,
        }
        update_name = self.ms.post(
            "/bom/nerve/node/update", json=payload, accepted_status=[requests.codes.ok]
        ).json()["operation_name"]

        self._log.info("Node update '%s' started", update_name)
        return update_name

    def get_deployment_list(self, update_name="", print_log=True):
        """Get list of update deployments filtered by update_name.

        Parameters
        ----------
        update_name : optional, str
            Name of the update to be filtered.
        print_info_log : bool, optional
            If set, the log level will be set to info, otherwise debug.
        """
        parameters = {
            "limit": 50,
            "page": 1,
            "contentType": "node_update",
            "filterBy[searchText]": update_name,
        }
        deploy_list = {"count": 0, "data": []}
        while True:
            deploy_list_single_read = self.ms.get(
                "/bom/deployment/list", params=parameters, accepted_status=[requests.codes.ok]
            ).json()
            parameters["page"] += 1
            deploy_list["data"] += deploy_list_single_read.get("data", [])
            deploy_list["count"] = deploy_list_single_read["count"]
            if len(deploy_list["data"]) == deploy_list_single_read["count"]:
                break

        active_deployments = []
        deployment_details = {}
        for deployment in deploy_list["data"]:
            deployment_active = False

            dep_details = self.get_deployment_details(deployment["_id"])
            deployment_details[deployment["_id"]] = dep_details
            deployment_active = any([task["isActive"] for task in dep_details["data"]])
            active_deployments.append(deployment_active)

        if print_log:
            self._print_deployment_info(deploy_list, deployment_details)
        return deploy_list, any(active_deployments), deployment_details

    def _print_deployment_info(self, deployment_list, deployment_details):
        """Print deployment information."""
        for deployment in deployment_list["data"]:
            self._log.info(
                "* %s: %s (started %s ago)",
                deployment["operation_name"],
                deployment["status"],
                str(
                    datetime.now(timezone.utc)
                    - datetime.fromisoformat(deployment["created"].replace("Z", "+00:00"))
                ).split(".")[0],
            )
            for task in deployment_details[deployment["_id"]]["data"]:
                self._log.info(
                    "  - %s (%s): %s %% %s",
                    task["deviceName"],
                    task["device"],
                    task["taskOptions"]["progress"],
                    task["taskOptions"]["status"],
                )
                if task["isFailed"]:
                    self._log.error(
                        "    - Error: %s %s",
                        task["errorFeedback"]["defautlMsg"],
                        task["errorFeedback"]["troubleshooting"],
                    )

    def get_deployment_details(self, deployment_id: str, print_info_log=True):
        """Read update deployment detail infos."""
        return self.ms.get(f"/bom/task/getDeployTasksInDeployment/{deployment_id}").json()

    def wait_for_all_deployments_beeing_finished(
        self, update_name="", max_deployment_time=1800, check_interval=60
    ):
        """Wait until all updates are finished or have failed."""
        time_start = time.time()
        last_time_status_printed = time_start
        deployment_successful = True

        status_old = []
        while True:
            deploy_list, active_deployments, dep_details = self.get_deployment_list(
                update_name, print_log=False
            )
            status_new = []
            for _deployment_id, details in dep_details.items():
                status_new = [task["taskOptions"]["status"] for task in details["data"]]
            if time.time() - last_time_status_printed > check_interval or status_old != status_new:
                last_time_status_printed = time.time()
                status_old = deepcopy(status_new)
                self._print_deployment_info(deploy_list, dep_details)

            deployment_states = {}
            for deployment in deploy_list["data"]:
                if deployment["status"] not in deployment_states:
                    deployment_states[deployment["status"]] = []
                deployment_states[deployment["status"]].append(deployment)
            if not active_deployments:
                self._print_deployment_info(deploy_list, dep_details)
                # check if any deployment is still active, if active_deployment is False, some update failed
                deployment_successful = all([deployment["isSuccess"] for deployment in deploy_list["data"]])
                details_success = all([status == "SUCCESS" for status in status_new])
                if deployment_successful or details_success:
                    self._log.info("All deployments are successful")
                else:
                    self._log.error("Some deployments failed")
                break
            if time.time() - time_start > max_deployment_time:
                self._log.warning("Timeout reached, deployments are still running")
                break
            time.sleep(min(check_interval, 5))
        return deployment_successful

    def get_update_history(self, include_onboarding=False):
        """Read the history of all updates.

        A list based on the serial-number of the node is created.
        Optionally the onboarding and last system start time can be included.
        """
        history = {}

        parameters = {"limit": 50, "page": 1, "contentType": "node_update"}
        deploy_list = {"count": 0, "data": []}
        while True:
            deploy_list_single_read = self.ms.get(
                "/bom/deployment/list", params=parameters, accepted_status=[requests.codes.ok]
            ).json()
            parameters["page"] += 1
            deploy_list["data"] += deploy_list_single_read.get("data", [])
            deploy_list["count"] = deploy_list_single_read["count"]
            if len(deploy_list["data"]) == deploy_list_single_read["count"]:
                break

        for update in deploy_list["data"]:
            self._log.debug(
                "%s, status: %s, date: %s, user: %s",
                update["operation_name"],
                update["status"],
                update["created"],
                update["userInitiated"],
            )
            update_tasks = self.ms.get(
                f"/bom/task/getDeployTasksInDeployment/{update['_id']}",
                params={
                    "limit": 200,
                    "filterBy": {
                        "isFinished": True,
                        "isFailed": True,
                        "isCancelled": True,
                        "inProgress": True,
                    },
                },
                accepted_status=[requests.codes.ok],
            ).json()
            for task in update_tasks["data"]:
                self._log.debug(
                    "  - %s (%s): %s %% %s, version: %s to %s",
                    task.get("deviceName"),
                    task["device"],
                    task["taskOptions"]["progress"],
                    task["taskOptions"]["status"],
                    task["version"]["oldVersion"],
                    task["version"]["newVersion"],
                )
                if task["device"] not in history:
                    history[task["device"]] = []
                history[task["device"]].append({
                    "deviceName": task.get("deviceName"),
                    "status": task["taskOptions"]["status"],
                    "progress": task["taskOptions"]["progress"],
                    "oldVersion": task["version"]["oldVersion"],
                    "newVersion": task["version"]["newVersion"],
                    "timestamp": update["created"],
                    "user": update["userInitiated"],
                })
        if include_onboarding:
            nodes_details = _MSNodeTree(self.ms)._get_tree(short_items=False, flat=True)
            for node in nodes_details:
                node_details = node["device"]
                device = node_details["serialNumber"]
                if device not in history:
                    history[device] = []
                    # node_details = MSNode(self.ms).Node(device).get_details()
                history[device].append({"timestamp": node_details["created"], "info": "Node created"})
                if node_details.get("lastSystemStart"):
                    history[device].append({
                        "timestamp": datetime.fromtimestamp(node_details["lastSystemStart"] // 1000).strftime(
                            "%Y-%m-%dT%H:%M:%S"
                        )
                        + f".{node_details['lastSystemStart'] % 1000:03d}Z",
                        "info": "Last system start",
                    })
                if node_details.get("lastTimeStatusUpdated"):
                    history[device].append({
                        "timestamp": node_details["lastTimeStatusUpdated"],
                        "info": "Last time status updated",
                    })
                if node_details.get("heartBeatReceived"):
                    history[device].append({
                        "timestamp": datetime.fromtimestamp(
                            node_details["heartBeatReceived"] // 1000
                        ).strftime("%Y-%m-%dT%H:%M:%S")
                        + f".{node_details['heartBeatReceived'] % 1000:03d}Z",
                        "info": "HeartBeat received",
                    })
        for _device, history_list in history.items():
            history_list = sorted(history_list, key=lambda x: x["timestamp"])  # noqa PLW2901
        return history
