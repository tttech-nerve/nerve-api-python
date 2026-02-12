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

"""Manage DNA releated function on a Node or MS.

Either import DNA (for managing DNA from a management system) or LocalDNA to manage DNA directly on a Node.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSDNA
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     dna = MSDNA(ms_handle, "SERIALNUM123")
    >>>     dna.get_status()
    <status of dna file of device with serial-number SERIALNUM123>
    >>> # Or manage DNA direclty on localUI of a node
    >>> from nerve_lib import NodeHandle
    >>> from nerve_lib import LocalDNA
    >>> with NodeHandle(<ip_address>) as node:
    >>>     dna_local_ui = LocalDNA(node)
    >>>     dna_local_ui.get_status()
    <status of dna file of node>
"""

import logging
import os
from io import BytesIO
from zipfile import BadZipFile
from zipfile import ZipFile

import requests
import yaml
from requests_toolbelt import MultipartEncoder


class DNACommon:
    """Common class for localUI and MS based DNA handling.

    Parameters
    ----------
    handle : type
        node or ms handle.
    base_url : str
        depending on node or ms handle, the base_url must be defined correct.
    log : type
        used logger to output logging data.
    """

    def __init__(self, handle, base_url: str, log: type):
        self.handle = handle
        self._log = log
        self.base_url = base_url

    def __get_files(self, location: str) -> dict:
        """Get DNA files as dict instead of zip-bin.

        Parameters
        ----------
        location : str
            current or target, defines which configuration shall be read

        Returns
        -------
        dict
            Read DNA configuration.
        """
        config_file = {}
        response = self.handle.get(os.path.join(self.base_url, location), accepted_status=[requests.codes.ok])
        if "application/x-yaml" in response.headers.get("Content-Type"):
            return yaml.safe_load(response.content)
        if "application/octet-stream" in response.headers.get("Content-Type"):
            try:
                zip_file = ZipFile(BytesIO(response.content))
                for cfile in zip_file.namelist():
                    self._log.info("Reading content of %s", cfile)
                    with zip_file.open(cfile) as file:
                        config_file[cfile] = yaml.safe_load(file.read())
                return config_file
            except BadZipFile:
                self._log.warning("Received DNA configuration is not a valid zip file")
                return {}

        self._log.error("Unexpected content-type received: %s", response.headers.get("Content-Type"))
        return {}

    def get_current(self) -> dict:
        """Get the current DNA configuration.

        Returns
        -------
        dict
            current configuration.
        """
        return self.__get_files("current")

    def get_target(self) -> dict:
        """Get the target DNA configuration.

        Returns
        -------
        dict
            target configuration.
        """
        return self.__get_files("target")

    def get_status(self) -> dict:
        """Get the DNA configuration status.

        Returns
        -------
        dict
            configuration status.
        """
        response = self.handle.get(os.path.join(self.base_url, "status"), accepted_status=[requests.codes.ok])
        return response.json()

    def put_target(
        self,
        config_file,
        continue_after_restart: bool = False,
        restart_all_wl: bool = False,
        remove_images: bool = True,
        sign_file: bool = False,
    ) -> dict:
        """Put new target configuration to the device.

        Parameters
        ----------
        config_file : Tuple[str, IO[bytes]] or dict
            Configuration file to be loaded to the device, either as tuple (filename, file-io stream) or
            as dictionary containing the configuration string (file-content).
        continue_after_restart : bool, optional
            If set to True, the configuration will continue to load after a device restart. The default is False.
        restart_all_wl : bool, optional
            If set to True, the configuration will restart all already deployed workloads. The default is False.

        Returns
        -------
        dict
            Configuration response from the device.
        """
        allowed_codes = [requests.codes.accepted, requests.codes.unauthorized, requests.codes.forbidden]
        while True:
            if type(config_file) is dict:
                # Expect a dict containing the correct config format
                file_name = "config.zip"
                zip_bin = BytesIO()
                with ZipFile(zip_bin, "w") as zip_object:
                    # Adding files that need to be zipped
                    zip_object.writestr("update_configuration.yaml", yaml.dump(config_file))
            elif type(config_file) is tuple:
                # Expect a File IO stream which contains the zip file
                file_name = config_file[0]
                zip_bin = config_file[1]
                zip_bin.seek(0, 0)
            else:
                msg = (
                    "Invalid Input, config_file should either by a valid dict or a tuple with"
                    "filename and FileIO stream"
                )
                raise ValueError(
                    msg,
                )
            m_enc = MultipartEncoder({"file": (file_name, zip_bin, "form-data")})

            params = {
                "continueInCaseOfRestart": str(continue_after_restart).lower(),
                "restartAllWorkloads": str(restart_all_wl).lower(),
                "removeDockerImages": str(remove_images).lower(),
            }
            # Only add signFile for MSDNA
            if sign_file is not None and type(self) is MSDNA:
                params["signFile"] = str(sign_file).lower()

            response = self.handle.put(
                os.path.join(self.base_url, "target"),
                params=params,
                content_type=m_enc.content_type,
                data=m_enc,
                accepted_status=allowed_codes,
                timeout=(7.5, 60),
            )
            if response.status_code == requests.codes.accepted:
                break

            self._log.debug("Not authorized, performing login and retry execution")
            self.handle.login()
            allowed_codes = [requests.codes.accepted]
        self._log.info("DNA config applied: %s", response.json().get("message", response.json()))
        return response.json()

    def put_target_re_apply(self) -> dict:
        """Reaply the target configuration.

        Returns
        -------
        dict
            response of the command.
        """
        response = self.handle.put(
            os.path.join(self.base_url, "target/re-apply"),
            accepted_status=[requests.codes.accepted],
        )
        self._log.info("DNA config reapply triggered: %s", response.json().get("message", response.json()))
        return response.json()

    def reapply_target(self) -> dict:
        """Same as put_target_re_apply."""
        self.put_target_re_apply()

    def patch_target_cancel(self) -> dict:
        """Cancle an ongoing configuration.

        Returns
        -------
        dict
            response of the command.
        """
        response = self.handle.patch(
            os.path.join(self.base_url, "target/cancel"),
            accepted_status=[requests.codes.accepted],
        ).json()
        try:
            self._log.info("DNA config canceled: %s", response.get("message", response))
        except AttributeError:
            self._log.warning("DNA config canceled, unexpected response: %s", response)
        return response

    def cancel_target(self) -> dict:
        """Same as patch_target_cancel."""
        self.patch_target_cancel()


class MSDNA(DNACommon):
    """Management system API commands to handle DNA of a device.

    Parameters
    ----------
    ms_handle : type
        handle to the MS 'nerve_lib.general_utils.MSHandle(...)'.
    node_serial_number : str
        Serial number of the connected node to execute the DNA functions with.
    """

    def __init__(self, ms_handle: type, node_serial_number: str):
        super().__init__(
            ms_handle,
            f"/nerve/dna/{node_serial_number}/",
            logging.getLogger(f"MSDNA-{node_serial_number}"),
        )


class LocalDNA(DNACommon):
    """Manage the DNA of a device directly using localUI API comamnds.

    Parameters
    ----------
    node_handle : type
        handle to the node 'nerve_lib.general_utils.NodeHandle(...)'.
    """

    def __init__(self, node_handle: type):
        super().__init__(
            node_handle,
            "/api/dna/",
            logging.getLogger(f"LocalDNA-{node_handle.serial_number}"),
        )
        node_handle.login()


class ServiceOSDNACommon(DNACommon):
    """Common class for localUI and MS based Service OS DNA handling."""

    def put_target(self, config_dict: dict) -> dict:
        """Apply target Service OS DNA configuration using a configuration dict.

        Parameters
        ----------
        config_dict : dict
            Configuration dictionary to upload as YAML.

        Returns
        -------
        dict
            Response from the device.
        """

        yaml_content = yaml.dump(config_dict, default_flow_style=False, allow_unicode=True)
        file_stream = BytesIO(yaml_content.encode("utf-8"))
        file_stream.seek(0)
        url = os.path.join(self.base_url, "target")
        self._log.info("Sending PUT request to URL: %s", url)
        accepted_status = [requests.codes.accepted, requests.codes.forbidden]
        while True:
            file_stream = BytesIO(yaml_content.encode("utf-8"))
            file_stream.seek(0)
            m_enc = MultipartEncoder({
                "file": ("update_configuration.yaml", file_stream, "application/x-yaml")
            })
            response = self.handle.put(
                url,
                content_type=m_enc.content_type,
                data=m_enc,
                accepted_status=accepted_status,
                timeout=(7.5, 60),
            )
            if response.status_code == requests.codes.forbidden:
                self.handle.login()
                accepted_status = [requests.codes.accepted]
                continue
            break
        try:
            return response.json()
        except Exception as e:
            self._log.error("Failed to parse response as JSON: %s", e)
            return {"error": str(e)}


class ServiceOSDNA(ServiceOSDNACommon):
    """Management system API commands to handle Service OS DNA of a device.

    Parameters
    ----------
    ms_handle : type
        handle to the MS 'nerve_lib.general_utils.MSHandle(...)'.
    node_serial_number : str
        Serial number of the connected node to execute the Service OS DNA functions with.
    """

    def __init__(self, ms_handle: type, node_serial_number: str):
        super().__init__(
            ms_handle,
            f"/nerve/service-os-dna/{node_serial_number}/",
            logging.getLogger(f"ServiceOSDNA-{node_serial_number}"),
        )


class LocalUIDNAServiceOS(ServiceOSDNACommon):
    """Manage Service OS DNA of a device via Local UI API commands.

    Parameters
    ----------
    node_handle : type
        Handle to the node (e.g. nerve_lib.general_utils.NodeHandle(...))
    """

    def __init__(self, node_handle: type):
        super().__init__(
            node_handle,
            "/api/service-os-dna/",
            logging.getLogger(f"LocalUIDNAServiceOS-{node_handle.serial_number}"),
        )
        node_handle.login()
