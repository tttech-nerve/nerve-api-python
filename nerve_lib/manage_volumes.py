# Copyright (c) 2025 TTTech Industrial Automation AG.
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

"""Manage Docker volumes and unused images on nodes from MS.

This module provides the DockerVolumes class for managing Docker volumes.
"""

import os
import time

import requests

from .general_utils import CheckStatusCodeError


class LocalDockerVolumes:
    """Handle Docker Volumes using localUI."""

    def __init__(self, node_handle):
        self.node = node_handle

        self._log = self.node._log.getChild("DockerVolumes")

    def get_volumes(self):
        """Get all Docker volumes on a node."""
        return self.node.get(
            "/api/docker-resources/volumes",
            accepted_status=[requests.codes.ok],
            timeout=(7.5, 30),
        ).json()

    def delete_volume(self, volume_name):
        """Delete a Docker volume.

        Parameters
        ----------
        volume_name : str
            Name of the volume to be deleted.
        """
        return self.node.delete(
            f"/api/docker-resources/volumes/{volume_name}",
            accepted_status=[requests.codes.no_content],
        )

    def import_volume_data(self, volume_name, file_path, import_timeout=30):
        """Import data to a volume.

        Parameters
        ----------
        volume_name : str
            Name of the volume.
        file_path : str
            Path to the file to be imported.
        """
        with open(file_path, "rb") as import_file:
            m_enc_data = {"file": (os.path.basename(file_path), import_file, "form-data")}

            resp = self.node.post(
                url=f"/api/docker-resources/volumes/{volume_name}/import",
                m_enc_data=m_enc_data,
                accepted_status=[requests.codes.ok],
                timeout=(7.5, import_timeout),
            )
        return resp.json()

    def export_volume_data(self, volume_name, file_path: str | None = None, export_timeout=30):
        """Export data from a volume.

        Parameters
        ----------
        volume_name : str
            Name of the volume.
        file_path : str | None
            Path to the file where the exported data will be saved. If None, the data will not be saved to a file.
        """
        if file_path and os.path.splitext(file_path)[1] != ".zip":
            raise ValueError("file_path must have a .zip extension")

        data = self.node.get(
            url=f"/api/docker-resources/volumes/{volume_name}/export",
            stream=True,
            accepted_status=[requests.codes.ok],
            timeout=(7.5, export_timeout),
        )
        if file_path:
            with open(file_path, "wb") as export_file:
                export_file.writelines(chunk for chunk in data.iter_content(chunk_size=8192))
        return data


class DockerVolumes:
    """Handle to Docker volumes on node from MS.

    Parameters
    ----------
    ms_handle : type
        handle to manage_workloads.Workloads object.
    """

    def __init__(self, ms_handle: type):
        self.ms = ms_handle

        self._log = self.ms._log.getChild("DockerVolumes")

    def get_volumes(self, dut_serial: type):
        """Get all Docker volumes on a node.

        Parameters
        ----------
        dut_serial : type
            reference to node serial number.
        Returns
        -------
        Response object from the MS API.
        """
        return self.ms.get(
            f"nerve/v2/node/{dut_serial}/docker-resources/volumes",
            accepted_status=[requests.codes.ok],
            timeout=(7.5, 30),
        ).json()

    def delete_volume(self, dut_serial: type, volume_name: str):
        """Delete a Docker volume.

        Parameters
        ----------
        dut_serial: type
            reference to node serial number.
        volume_name: str
            docker volume name.
        Returns
        -------
        Response object from the MS API.
        """
        return self.ms.delete(
            f"nerve/v2/node/{dut_serial}/docker-resources/volumes/{volume_name}",
            accepted_status=[requests.codes.no_content],
        )

    def delete_all_volumes(self, dut_serial: str):
        """Delete all docker volumes on a node with improved error handling and logging."""
        data = self.get_volumes(dut_serial)
        if "volumes" not in data or not isinstance(data["volumes"], list):
            self._log.error("Unexpected response format: %s", data)
            raise RuntimeError(f"Unexpected response format: {data}")

        for volume in data["volumes"]:
            self._log.info("Deleting volume: %s", volume["name"])
            self.delete_volume(dut_serial, volume["name"])

        self._log.info("All volumes deleted for node %s", dut_serial)

    def import_volume_data(self, dut_serial, volume_name, file_path, import_timeout=30):
        """Import data to a volume with improved error handling."""
        try:
            with open(file_path, "rb") as f:
                m_enc_data = {"file": (os.path.basename(file_path), f, "form-data")}

                return self.ms.post(
                    url=f"/nerve/v2/node/{dut_serial}/docker-resources/volumes/{volume_name}/import",
                    m_enc_data=m_enc_data,
                    accepted_status=[requests.codes.ok],
                    timeout=(7.5, import_timeout),
                )
        except FileNotFoundError:
            self._log.error("File not found: %s", file_path)
            raise

    def export_volume_data_ms(self, dut_serial, volume_name, export_timeout=30):
        """Export data from a volume with improved error handling."""

        return self.ms.post(
            url=f"/nerve/v2/node/{dut_serial}/docker-resources/volumes/{volume_name}/export",
            accepted_status=[requests.codes.no_content],
            timeout=(7.5, export_timeout),
        )
        # Volume data export will be triggered only.
        # Export can be found in /nerve_node/storage/docker-volume-backups-export/{dut_serial}/{backupName}
        # The backupName can be obtained by checking get_volumes (backupInfo->backupName)

    def check_export_status(self, dut_serial, volume_name, retry_timeout=60):
        """Check the status of the export operation with improved error handling."""
        start_time = time.time()
        while time.time() - start_time < retry_timeout:
            try:
                response = self.get_volumes(dut_serial).json()
                volume = next((v for v in response.get("volumes", []) if v["name"] == volume_name), None)
                if not volume:
                    raise RuntimeError(f"Volume '{volume_name}' not found in response: {response}")

                for info in volume.get("backupInfo", []):
                    if info["action"] == "export" and info["status"] == "COMPLETED":
                        return info["backupName"]
            except CheckStatusCodeError as ex:
                self._log.warning("Error while checking export status of %s: %s", volume_name, ex)
            time.sleep(10)
        raise TimeoutError(
            f"Export did not complete within {retry_timeout} seconds for volume '{volume_name}'."
        )
