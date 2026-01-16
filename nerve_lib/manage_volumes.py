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
from requests_toolbelt import MultipartEncoder


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
        )

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
        response = self.get_volumes(dut_serial)
        if response.status_code != requests.codes.ok:
            self.ms._log.error("Failed to fetch volumes: %s - %s", response.status_code, response.text)
            raise RuntimeError(f"Failed to fetch volumes: {response.status_code} - {response.text}")
        data = response.json()
        if "volumes" not in data or not isinstance(data["volumes"], list):
            self.ms._log.error("Unexpected response format: %s", data)
            raise RuntimeError(f"Unexpected response format: {data}")
        volumes = [volume["name"] for volume in data["volumes"]]
        for volume in volumes:
            try:
                self.ms._log.info("Deleting volume: %s", volume)
                self.delete_volume(dut_serial, volume)
            except Exception as ex:
                self.ms._log.warning("Failed to delete volume %s: %s", volume, ex)
        self.ms._log.info("All volumes deleted for node %s", dut_serial)

    def import_volume_data_ms(self, dut_serial, volume_name, file, import_timeout=30):
        """Import data to a volume with improved error handling."""
        try:
            with open(file, "rb") as f:
                m_enc = MultipartEncoder({"file": (os.path.basename(file), f, "form-data")})
                self.ms.login()
                sessionid = self.ms._add_header["sessionid"]
                headers = {
                    "Connection": "close",
                    "Content-Type": m_enc.content_type,
                    "sessionId": sessionid,
                }
                return self.ms.post(
                    url=f"/nerve/v2/node/{dut_serial}/docker-resources/volumes/{volume_name}/import",
                    headers=headers,
                    data=m_enc,
                    accepted_status=[requests.codes.ok],
                    timeout=(7.5, import_timeout),
                )
        except FileNotFoundError:
            self.ms._log.error("File not found: %s", file)
            raise
        except Exception as ex:
            self.ms._log.error("Failed to import volume data: %s", ex)
            raise

    def export_volume_data_ms(self, dut_serial, volume_name, export_timeout=30):
        """Export data from a volume with improved error handling."""
        try:
            self.ms.login()
            sessionid = self.ms._add_header["sessionid"]
            headers = {
                "Connection": "keep-alive",
                "sessionId": sessionid,
            }
            return self.ms.post(
                url=f"/nerve/v2/node/{dut_serial}/docker-resources/volumes/{volume_name}/export",
                headers=headers,
                accepted_status=[requests.codes.no_content],
                timeout=(7.5, export_timeout),
            )
        except Exception as ex:
            self.ms._log.error("Failed to export volume data: %s", ex)
            raise

    def check_export_status(self, dut_serial, volume_name, retry_timeout=60):
        """Check the status of the export operation with improved error handling."""
        start_time = time.time()
        while time.time() - start_time < retry_timeout:
            try:
                response = self.get_volumes(dut_serial).json()
                for volume in response.get("volumes", []):
                    if volume["name"] != volume_name:
                        continue
                    for info in volume.get("backupInfo", []):
                        if info["action"] != "export":
                            continue
                        if info["status"] == "COMPLETED":
                            return info["backupName"]
            except Exception as ex:
                self.ms._log.warning("Error while checking export status: %s", ex)
            time.sleep(10)
        raise TimeoutError(
            f"Export did not complete within {retry_timeout} seconds for volume '{volume_name}'."
        )
