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


"""Provides several classes to access a node or a management system.

    - class NodeHandle: Allows Nerve Node access over localUI or SSH. a ssh-tunnel to the localUI is
        automatically created
    - class MSHandle: Allows to access a Nerve Management System

    The creation of a class will also setup the "setup_logging" to allow a automatic logging output.
    The logging level can be changed by setting the required loglevel using an ENV-var before
    loading the module, or by changing the level of the root logger, e.g.

    >>> import logging
    >>>
    >>> logging.root.handlers[0].setLevel("WARNING")

Usable ENV Vars:
    - LOGGING_LEVEL: Default log-level to be used, if not defined, level INFO is selected.
    - DEBUG_LOG_FILE: file name of a log file which will contain all logs including debug output
    - SSH_USR: username of a node for ssh-access
    - SSH_PSW: password of a node for ssh-access
    - NODE_USR: username to access localUI of a node
    - NODE_PSW: password to access localUI of a node
    - MS_USR: username for a management system
    - MS_PSW: password of a management system
"""

import base64
import json
import logging
import os
import socket
import time
import weakref
from http.client import responses
from typing import Optional
from urllib.parse import urljoin

import paramiko
import requests
import sshtunnel
import urllib3
from scp import SCPClient
from sshtunnel import SSHTunnelForwarder

urllib3.disable_warnings()


def setup_logging(compact=False):
    """Create logging output configuration if it does not exist already.

    Usable ENV Vars:
        - LOGGING_LEVEL: Default log-level to be used, if not defined, level INFO is selected.
        - DEBUG_LOG_FILE: file name of a log file which will contain all logs including debug output
    """
    # remove all handlers which are NOTSET
    logging.root.handlers = [handler for handler in logging.root.handlers if handler.level != logging.NOTSET]

    # add stream handler
    stream_handler_configured = any([
        isinstance(handler, logging.StreamHandler) for handler in logging.root.handlers
    ])
    if not stream_handler_configured:
        logging.basicConfig(
            level=logging.DEBUG,
            format="{levelname:<7} {name:<20.20} :: {message}"
            if compact
            else "{levelname:<7} {name:<35.35} {filename:>20.20}-{lineno:<4} :: {message}",
            style="{",
        )
        logging.root.handlers[-1].setLevel(os.environ.get("LOGGING_LEVEL", "INFO").upper())
        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)  # Suppress paramiko debug messages
        logging.getLogger("pykeepass").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    # add file handler
    if os.environ.get("DEBUG_LOG_FILE", ""):
        file_handler_configured = any([
            isinstance(handler, logging.FileHandler) for handler in logging.root.handlers
        ])
        if not file_handler_configured:
            logger = logging.getLogger()
            file_handler = logging.FileHandler(os.environ.get("DEBUG_LOG_FILE"))
            formatter = logging.Formatter(
                "{asctime} {levelname:<7} {name:<25} {filename:>25.25}-{lineno:<4} :: {message}",
                style="{",
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            logger.addHandler(file_handler)


class CheckStatusCodeError(Exception):
    """Error for Invalid response status codes.

    msg.status_code: received status_code
    msg.value: string error message
    """

    def __init__(self, message: str, status_code: int, response_text: str):
        super().__init__(message)

        self.status_code = status_code
        self.value = message
        self.response_text = response_text


class SSHTunnelError(Exception):
    """Error for SSH Tunnel related issues."""


class SshGeneral:
    """Allow to access a device over ssh and execute commands.

    Parameters
    ----------
    ip_addr : str
        IP address of the device.
    user : str
        ssh username to login.
    password : str
        ssh password to login.
    """

    def __init__(self, ip_addr: str, user: str = "", password: str = ""):
        setup_logging()
        self.ip_addr = ip_addr
        self._ssh_usr = user or os.environ.get("SSH_USR")
        self._ssh_psw = password or os.environ.get("SSH_PSW")
        self._log = logging.getLogger(f"SSH-{ip_addr}")

    def __enter__(self):
        """Enter function when using with statement."""
        return self

    def __exit__(self, *args):
        """Exit function when using with statement."""

    def connect(self, timeout: float = 30.0, key: Optional[str] = None, compress: bool = False) -> type:
        """Create an ssh connection to a device.

        Parameters
        ----------
        timeout : float, optional
            an optional timeout (in seconds) for the TCP connect. The default is 30.0.
        key : str, optional
            an optional private key to use for authentication. The default is None.
        compress : bool, optional
            set to True to turn on compression. The default is False.

        Returns
        -------
        type
            get handle of a paramiko.SSHClient object.

        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ip_addr = self.ip_addr[0] if type(self.ip_addr) is tuple else self.ip_addr
        port = self.ip_addr[1] if type(self.ip_addr) is tuple else 22
        if key is not None:
            k = paramiko.RSAKey.from_private_key_file(key)
            ssh.connect(
                ip_addr,
                port=port,
                username=self._ssh_usr,
                pkey=k,
                timeout=timeout,
                compress=compress,
            )
        else:
            ssh.connect(
                ip_addr,
                port=port,
                username=self._ssh_usr,
                password=self._ssh_psw,
                timeout=timeout,
                compress=compress,
            )

        return ssh

    def execute(
        self,
        cmd: str,
        timeout: float = 30.0,
        ssh: Optional[type] = None,
        as_sudo: bool = False,
        compress: bool = False,
        sudo_psw: Optional[str] = None,
    ) -> str:
        """Execute a ssh command on a device.

        Parameters
        ----------
        cmd : str
            command to be executed.
        timeout : float, optional
            set command's channel timeout. See .Channel.settimeout. The default is 30.0.
        ssh : type, optional
            paramiko.SSHCLient. If defined an already existing connection will be used. The default is None.
        as_sudo : bool, optional
            Set to True to execute a command as sudo. The default is False.
        compress : bool, optional
            set to True to turn on compression. The default is False.
        sudo_psw : str, optional
            If as_sudo is used, the sudo password can be provided here. The default is None.

        Returns
        -------
        str
            concatenated output of stdout and stderr.
        """
        if as_sudo:
            if sudo_psw is None:
                sudo_psw = self._ssh_psw
            cmd = f"echo {sudo_psw} | sudo -S {cmd}"
        output = ""
        ssh_ = ssh or self.connect(timeout, compress=compress)

        _stdin, stdout, stderr = ssh_.exec_command(cmd, timeout=timeout)
        output += "".join(stdout.readlines())
        output += "".join(stderr.readlines())
        if not ssh:
            ssh_.close()
        return output.replace("[sudo] password for admin: ", "")

    def reboot(self):
        """Execute a reboot command over ssh on a device."""
        self._log.info("Rebooting the DUT")
        self.execute("reboot", as_sudo=True)
        time.sleep(30)

    def check_port_open(self, port: int) -> bool:
        """Test is port open on Node, e.g. port 22 (SSH).

        Parameters
        ----------
        port : int
            port to be checked.

        Returns
        -------
        bool
            validates if port is open.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        try:
            ip_addr = self.ip_addr[0] if type(self.ip_addr) is tuple else self.ip_addr
            s.connect((ip_addr, int(port)))
            s.shutdown(socket.SHUT_RDWR)
            return True
        except Exception:
            return False
        finally:
            s.close()

    def copy(self, file_name: str, file_path: str = "images/", max_retries: int = 3) -> bool:
        """Copy a file via SCP to a device.

        Parameters
        ----------
        file_name : str
            name of the file, will be the name in home directory of the device.
        file_path : str, optional
            local-file path. The default is "images/".
        max_retries : int, optional
            executing a retry in case the copy action failes. The default is 3.

        Returns
        -------
        bool
            validates if the copy execution was successful.
        """
        retry_count = 0
        while True:
            self._log.info("    - Copy file %s", file_name)
            try:
                with (
                    self.connect() as connection,
                    SCPClient(connection.get_transport(), socket_timeout=60.0) as scp,
                ):
                    scp.put(os.path.join(file_path, file_name), file_name)
                return True
            except Exception as ex_msg:
                self._log.error("Failed to copy file to device: %s", ex_msg)
                if retry_count >= max_retries:
                    return False
                retry_count += 1
                self._log.info("copy file failed, executing retry in 20 sec...")
                time.sleep(20)


class ManageSshTunnel:
    """Manage SSH Tunnels required to access e.g. localUI of a node.

    Parameters
    ----------
    user : str, optional
        ssh user to connect to the device. The default is None.
    password : str, optional
        ssh password to connect to the device. The default is None.
    log : type, optional
        handle of logging.getLogger(...). The default is None.
    """

    def __init__(
        self, user: Optional[str] = None, password: Optional[str] = None, log: Optional[type] = None
    ):
        setup_logging()
        if not log:
            log = logging.getLogger("SSH-Tunnel")
        self._log = log
        self.__log_forwarder = logging.getLogger("SSHTunnelForwarder")
        self.__log_forwarder.setLevel(logging.CRITICAL)

        sshtunnel.SSH_TIMEOUT = 10
        sshtunnel.TUNNEL_TIMEOUT = 10

        self._ssh_usr = user or os.environ.get("SSH_USR")
        self._ssh_psw = password or os.environ.get("SSH_PSW")

        # for debugging
        # sshtunnel.DEFAULT_LOGLEVEL = 1

        # timeout bellow will not work.. so timeout will be ~120 sec.
        # https://github.com/pahaz/sshtunnel/issues/228

        self._tunnels = {}
        self._finalizer = weakref.finalize(self, self._cleanup, self._log, self._tunnels)

    def __enter__(self):
        """Enter function when using with statement."""
        return self

    def __exit__(self, *args):
        """Exit function when using with statement."""
        self._finalizer()

    @staticmethod
    def _cleanup(log, tunnels):
        """Safely cleanup class.

        If the class shall be manually cleaned, call this function:

        >>> ssh_tunnel._finalizer()
        """
        for tunnel_key, tunnel in tunnels.items():
            log.debug("Closing Tunnel %s", tunnel_key)
            if tunnel.is_active or tunnel.is_alive:
                tunnel.stop()
        tunnels = {}

    def create_tunnel(
        self,
        ip_address,
        remote_bind: tuple[str, int],
        local_port: Optional[int] = None,
    ) -> type:
        """Create a specific ssh-tunnel to a node.

        Example:

        >>> ssh_tunnel = ManageSshTunnel(usr, password, logging.getLogger("CustomName"))
        >>> ssh_tunnel.create_tunnel("172.16.0.1", ("172.20.2.1", 3333), 3333)
        <returns tunnel-handle>

        Parameters
        ----------
        ip_address : str
            ip-address of the node.
        remote_bind : tuple[str, int]
            tuple containing node containers ip address and port to connect to.
        local_bind : tuple[str, int]
            tuple containing local ip address and port to connect to.

        Returns
        -------
        type
            SSHTunnel handle.

        """
        if not local_port:
            local_port = remote_bind[1]

        # ensure that IP is a string and port is an integer
        ip_address = (
            (str(ip_address[0]), int(ip_address[1])) if type(ip_address) is tuple else str(ip_address)
        )

        remote_bind = (str(remote_bind[0]), int(remote_bind[1]))
        local_bind = ("127.0.0.1", int(local_port))

        tunnel_key = f"{ip_address}:: {remote_bind[0]}:{remote_bind[1]} -> {local_bind[1]}"

        if tunnel_key in self._tunnels:
            self._log.debug("Tunnel %s existed, nothing todo", tunnel_key)
            return self._tunnels[tunnel_key]
        self._log.debug("Creating ssh tunnel for %s", tunnel_key)

        try:
            tunnel = SSHTunnelForwarder(
                ssh_address_or_host=ip_address,
                ssh_username=self._ssh_usr,
                ssh_password=self._ssh_psw,
                remote_bind_address=remote_bind,
                local_bind_address=local_bind,
                logger=self.__log_forwarder,
            )

            tunnel.start()
            self._log.debug("- is ssh tunnel active/alive?: %s/%s", tunnel.is_active, tunnel.is_alive)
            if tunnel.is_active and tunnel.is_alive:
                self._tunnels[tunnel_key] = tunnel

                return self._tunnels.get(tunnel_key)

            self._log.error("Could not establish tunnel, tunnel not active")
            return None
        except Exception as ex_msg:
            self._log.error("Could not establish tunnel: %s", ex_msg)
            return None

    def remove_tunnel(self, local_port: int) -> None:
        """Remove a tunnel and close the connection.

        Parameters
        ----------
        local_bind : tuple[str, int]
            local bind information (ip-address, port).
        """
        for tunnel_key, tunnel in self._tunnels.items():
            if tunnel.local_bind_address == ("127.0.0.1", local_port):
                self._log.info("Removing tunnel %s", tunnel_key)
                try:
                    if tunnel.is_active or tunnel.is_alive:
                        tunnel.stop()
                except sshtunnel.BaseSSHTunnelForwarderError:
                    self._log.warning("Could not stop tunnel before removing")
                del self._tunnels[tunnel_key]
                return
        self._log.warning("Tunnel with local port %s does not exist", local_port)

    def refresh_tunnels(self) -> bool:
        """Check if created tunnels are active and stop/start them in case they are not running.

        Returns
        -------
        bool
            If false: Refreshing tunnel failed, a warning is printed in addition.

        """
        ret_val = True
        for tunnel_key, tunnel in self._tunnels.items():
            if tunnel.is_active and tunnel.tunnel_is_up[tunnel.local_bind_address] and tunnel.is_alive:
                continue

            self._log.info("Refreshing tunnel %s", tunnel_key)
            try:
                tunnel.stop()
                tunnel.start()
            except sshtunnel.BaseSSHTunnelForwarderError:
                self._log.warning("Could not refresh tunnel, device is probably not reachable")
                ret_val = False
        return ret_val


class RequestGeneral(requests.Session):
    """Manage Requests to Nodes and MS.

    The class can be added as super-class to other instances.
    It will handle some basic request operations
    and create exceptions in case the return status is unexpected.

    Parameters
    ----------
    url : str
        URL to execute requests mehtods on.
    api_path : str
        default api-path to be used.
        If requests executed with url "/path" will overwrite the api_path.
        Creating a request with url "path" will create a request on /api_path/path.
    log : type
        logging.getLogger(...) handle to be used.

    Returns
    -------
    None.

    """

    def __init__(self, url: str, api_path: str, log: type):
        setup_logging()
        super().__init__()

        self.url = url
        self.api_url = urljoin(self.url, api_path)
        self._log = log

        self._add_header = {
            "Content-Type": "application/json",
            "accept": "application/json, text/plain, */*",
        }
        self._add_cookies = {}
        self._add_auth = {}

    def request(
        self,
        method: str,
        url: str,
        accepted_status: list = [requests.codes.ok, requests.codes.no_content],
        content_type: str = "application/json",
        **kwargs,
    ) -> type:
        """Overwrite default request function.

        Function is extended with checking for accepted_status and adds different Headers required for
        connecting to the device.

        Parameters
        ----------
        method : str
            method for the new :class:`Request` object..
        url : str
            URL for the new Request object..
        accepted_status : list, optional
            list of allowed status responses, others will create an error.
            The default is [requests.codes.ok, requests.codes.no_content].
        content_type : str, optional
            conent type of the request. The default is "application/json".
        **kwargs : TYPE
            additional key values as defined in requests.request object.

        Returns
        -------
        type
            requests.Response object.

        """
        if "http" not in url:
            url = urljoin(self.api_url, url)
        self._add_header["Content-Type"] = content_type
        if "timeout" not in kwargs:
            kwargs["timeout"] = (7.5, 5) if method.upper() == "GET" else (7.5, 30)
        if "headers" not in kwargs:
            kwargs["headers"] = self._add_header
        if "cookies" not in kwargs and self._add_cookies:
            kwargs["cookies"] = self._add_cookies
        if "auth" not in kwargs and self._add_auth:
            kwargs["auth"] = self._add_auth
        time_start = time.time()

        def execute_request(method: str, url: str, retry: bool, request_handle: requests.Session, **kwargs):
            try:
                response = request_handle.request(method, url, **kwargs)
            except (requests.ReadTimeout, requests.ConnectTimeout) as ex_msg:
                if retry:
                    self._log.warning(
                        "%s was raised (response-time: %s-%s %s), trying to execute command again, ...",
                        ex_msg.__class__.__name__,
                        method.upper(),
                        url,
                        round(time.time() - time_start, 2),
                    )
                    response = execute_request(
                        method, url, retry=False, request_handle=request_handle, **kwargs
                    )
                else:
                    msg_error = f"{ex_msg.__class__.__name__} was raised (response-time: {method.upper()}-{url} {round(time.time() - time_start, 2)}), giving up."

                    self._log.error(msg_error)
                    new_error_msg = f"{msg_error}\nOriginal exception message: {ex_msg!s}"

                    raise type(ex_msg)(new_error_msg)
            return response

        self._log.log(
            1,
            "Execute %s:%s with:\nheaders: %s\ncookies: %s",
            method,
            url,
            kwargs.get("headers"),
            kwargs.get("cookies"),
        )

        response = execute_request(method, url, retry=True, request_handle=super(), **kwargs)
        return self._check_response(method, response, accepted_status)

    def _check_response(self, method: str, response: type, accepted_status: list) -> type:
        """Check if response status code is in accepted status codes."""

        def _shorten_string(input_str: str, max_length: int = 1000) -> str:
            """Reduce string length.

            Parameters
            ----------
            input_str : str
                full input string.
            max_length : int, optional
                maximal number of chars to be printed. The default is 1000.

            Returns
            -------
            str
                shortend string with info that it had been cut for printing.
            """
            if (length := len(input_str)) > max_length:
                self._log.debug("cutting Original string: %s", input_str)
                input_str = input_str[:max_length]
                return f"{input_str} ...[output str-len: {length}char]"
            return input_str

        if response.status_code not in accepted_status:
            err_msg = f"FAILED! - {method.upper()} {response.url} {response.reason}"
            err_msg += f"-> [{responses[response.status_code]}:{response.status_code}]"

            response_text_complete = ""
            if response.status_code != requests.codes.no_content:
                response_text_complete = response.text
                try:
                    err_msg += f": {_shorten_string(json.dumps(response.json(), indent=4))}"
                except requests.exceptions.JSONDecodeError:
                    err_msg += f": {_shorten_string(response.text)}"
                except json.decoder.JSONDecodeError:
                    err_msg += f": {_shorten_string(response.text)}"
            raise CheckStatusCodeError(err_msg, response.status_code, response_text_complete)
        return response


class NodeHandle(RequestGeneral):
    """Node requests and ssh connection management.

    Example:

    >>> node = NodeHandle("10.248.100.123", api_path="/licenses/api/") # login data provided over ENV vars
    >>> node.get("getActiveLicenses") # Get current used license info
    <Response [200]>
    >>> node.get("/api/dna/status") # Get status of dna (not using api_path as the url starts with "/")
    <Creating tunnel>
    <Login to device>
    <Response [200]>

    Parameters
    ----------
    ip_addr : str
        ip address of the node to connect to.
    user : str, optional
        localUI username. The default is ENV-var NODE_USR.
    password : str, optional
        localUI password. The default is ENV-var NODE_PSW.
    ssh_user : str, optional
        ssh username. The default is ENV-var SSH_USR.
    ssh_password : str, optional
        ssh password. The default is ENV-var SSH_PSW.
    api_path : str, optional
        default api_path to execute requests on. The default is "/".
    serial_number : str, optional
        serial-number of nerve node. The default is None.
    local_ui_port : int, optional
        localUI port of the node. The default is 3333.
    local_ui_ip_addr : str, optional
        LocalUI ip address of the node. The default is "172.20.2.1".
    local_bind_port : int, optional
        bind port of localUI in local connection. The default is 3333.
    """

    def __init__(
        self,
        ip_addr: str,
        user: Optional[str] = None,
        password: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_password: Optional[str] = None,
        api_path: str = "/",
        serial_number: Optional[str] = None,
        local_ui_port: int = 3333,
        local_ui_ip_addr: str = "172.20.2.1",
        local_bind_port: int = 3333,
    ):
        self.ssh_tunnel = ManageSshTunnel(
            user=ssh_user,
            password=ssh_password,
            log=logging.getLogger(f"SSH-Tunnel-{serial_number}"),
        )
        self.ssh = SshGeneral(ip_addr, user=ssh_user, password=ssh_password)

        self.ip_addr = ip_addr
        self.usr = user or os.environ.get("NODE_USR")
        self.psw = password or os.environ.get("NODE_PSW")
        try:
            self.serial_number = serial_number or json.loads(
                self.ssh.execute("cat /etc/node_config.json"),
            ).get("serialId", "unknown-sid")
        except json.decoder.JSONDecodeError:
            self.serial_number = "unknown-sid"

        self.local_ui_port = local_ui_port
        self.local_ui_ip_addr = local_ui_ip_addr
        self.local_bind_port = local_bind_port
        self.tunnel_node_created = False

        super().__init__(
            url=f"http://127.0.0.1:{local_bind_port}",
            api_path=api_path,
            log=logging.getLogger(f"Node-{serial_number}"),
        )

        self._is_logged_in = False

        self._finalizer = weakref.finalize(self, self._cleanup, weakref.ref(self))

    def __enter__(self):
        """Enter function when using with statement."""
        return self

    def __exit__(self, *args):
        """Exit function when using with statement."""
        self._finalizer()

    def __del__(self):
        """Destructor to ensure that finalizer is called."""
        self._finalizer()

    @staticmethod
    def _cleanup(handle_ref):
        """Safely cleanup class.

        If the class shall be manually cleaned, call this function:

        >>> node._finalizer()
        """
        try:
            node = handle_ref()
        except Exception:  # pragma: no cover - defensive
            node = None

        if node:
            if node._is_logged_in:
                node.logout()  # close session before closing tunnels
            node._log.debug("Removing ssh-tunnels")
            node.ssh_tunnel._finalizer()

    def create_tunnel_node(self):
        """Create a ssh-tunnel to the localUI of a node."""
        if not self.tunnel_node_created:
            remote_bind = (self.local_ui_ip_addr, self.local_ui_port)
            if self.ssh_tunnel.create_tunnel(self.ip_addr, remote_bind, self.local_bind_port) is not None:
                self.tunnel_node_created = True
        return self.tunnel_node_created

    def request(self, method, url, *args, **kwargs) -> type:
        """Execute a request on the node."""
        if not self.create_tunnel_node():
            msg = f"Tunnel to port {self.local_bind_port} could not be created, no request can be executed on local-ui"
            raise SSHTunnelError(msg)

        accepted_status = kwargs.get(
            "accepted_status",
            [requests.codes.ok, requests.codes.no_content, requests.codes.created],
        )
        adding_error_handling = []
        for error_code in [
            requests.codes.unauthorized,
            requests.codes.not_allowed,
            requests.codes.bad_gateway,
        ]:
            if error_code not in accepted_status:
                accepted_status.append(error_code)
                adding_error_handling.append(error_code)

        kwargs["accepted_status"] = accepted_status

        time_start = time.time()
        timeout = 60
        connection_error_count = 0
        retry_count = 0
        while (time.time() - time_start) < timeout:
            try:
                response = super().request(method, url, *args, **kwargs)
                if response.status_code in adding_error_handling:
                    if retry_count > 0:
                        break
                    if response.status_code in {requests.codes.unauthorized}:
                        time.sleep(1)
                        self.login()
                        retry_count += 1
                    else:
                        self._log.warning(
                            "%s: %s failed with exit code %s [%d], retry executed in 10 sec",
                            method.upper(),
                            url,
                            responses[response.status_code],
                            response.status_code,
                        )
                        time.sleep(10)
                        retry_count += 1
                else:
                    break
            except requests.exceptions.ConnectionError as ex_msg:
                if (
                    connection_error_count < 1
                    and kwargs.get("content_type", "application/json") == "application/json"
                ):
                    connection_error_count += 1
                    self._log.warning(
                        "Received a ConnectionError when accessing %s:%s, execute command again",
                        method,
                        url,
                    )
                    if (time.time() - time_start) < (timeout - 10):
                        self.ssh_tunnel.refresh_tunnels()
                        time.sleep(1)
                        continue

                self._log.error(
                    "Received a ConnectionError after %ssec when executing the command %s:%s",
                    int(time.time() - time_start),
                    method,
                    url,
                )
                raise ex_msg

        if not time.time() - time_start < timeout or retry_count > 0:  # If login did not work (timed out)
            for error_code in adding_error_handling:
                del accepted_status[accepted_status.index(error_code)]
            super()._check_response(method, response, accepted_status)
        return response

    def set_ssh_credentials(self, user: str, password: str):
        """Set ssh credentials for ssh-tunnel management and ssh-connection.

        Parameters
        ----------
        user : str
            ssh username.
        password : str
            ssh password.
        """
        self.ssh_tunnel._ssh_usr = user
        self.ssh_tunnel._ssh_psw = password
        self.ssh._ssh_usr = user
        self.ssh._ssh_psw = password

    def login(self, user: str = "", password: str = ""):
        """Login to Node."""
        self._log.debug("login with URL %s", self.url)
        self.ssh_tunnel.refresh_tunnels()

        self.usr = user or self.usr
        self.psw = password or self.psw

        basic_auth_text = f"{self.usr}:{self.psw}"
        headers = {
            "Content-Type": "application/json",
            "accept": "application/json, text/plain, */*",
            "Authorization": f"Basic {base64.b64encode(basic_auth_text.encode('utf-8')).decode('utf-8')}",
        }

        try:
            if self._is_logged_in:
                self.logout()  # close old session before logging in again
            response = self.post(
                "/api/auth/login",
                json={"username": self.usr, "password": self.psw},
                headers=headers,
                accepted_status=[requests.codes.ok],
            )
            self._is_logged_in = True
            return response

        except urllib3.exceptions.MaxRetryError:
            self._log.error("Login failed, max retry exceeded")
            time.sleep(5)
        except urllib3.exceptions.NewConnectionError:
            self._log.error("Login failed, can't establish new connection")
            time.sleep(5)
        except requests.exceptions.ConnectionError:
            self._log.error("Login failed, request ConnectionError is raised!")
            time.sleep(5)

    def logout(self):
        """Logout from Node."""
        self._log.debug("Logout from Node")
        response = self.get(
            "/api/auth/logout", accepted_status=[requests.codes.no_content, requests.codes.unauthorized]
        )
        self._is_logged_in = False
        return response


class MSHandle(RequestGeneral):
    """Connect to a MS and handle requests.

    Parameters
    ----------
    ms_url : str
        MS URL to connect to, e.g. test.nerve.cloud.
    user : str, optional
        username to login on MS. The default is ENV-var MS_USR.
    password : str, optional
        password to logon on MS. The default is ENV-var MS_PSW.
    """

    def __init__(self, ms_url: str, user: str = "", password: str = ""):
        if ms_url.startswith("http"):
            self.ms_url = ms_url.split("://")[1]
            super().__init__(url=ms_url, api_path="/", log=logging.getLogger(f"MS-{ms_url}"))
        else:
            self.ms_url = ms_url
            super().__init__(url=f"https://{ms_url}", api_path="/", log=logging.getLogger(f"MS-{ms_url}"))
            self._log.debug("no http/https in URL, adding https://")

        self.verify = False

        self.usr = user or os.environ.get("MS_USR", "")
        self.psw = password or os.environ.get("MS_PSW", "")

        self._is_logged_in = False

        self._finalizer = weakref.finalize(self, self._cleanup, weakref.ref(self))

        self.__ms_version = None

    def __enter__(self):
        """Enter function when using with statement."""
        return self

    def __exit__(self, *args):
        """Exit function when using with statement."""
        self._finalizer()

    def __del__(self):
        """Destructor to ensure cleanup."""
        self._finalizer()

    @staticmethod
    def _cleanup(handle_ref):
        """Safely cleanup class.

        If the class shall be manually cleaned, call this function:

        >>> ms_handle._finalizer()
        """

        try:
            ms_handle = handle_ref()
        except Exception:  # pragma: no cover - defensive
            ms_handle = None

        if ms_handle:
            ms_handle._log.debug("Removing MS Handle")
            if ms_handle._is_logged_in:
                ms_handle.logout()  # close session before removing handle

    @property
    def version(self) -> str:
        """Get the version of the MS.

        Returns
        -------
        str
            version of the MS.
        """
        if not self.__ms_version:
            self.__ms_version = self.get("/nerve/update/cloud/current-version").json().get("currentVersion")
        return self.__ms_version

    def version_smaller_than(self, version: str) -> bool:
        """Check if the MS version is smaller than the provided version.

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
            self._log.info("No valid version found, assuming version is latest")
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

    def request(self, method, url, *args, **kwargs) -> type:
        """Execute a request on the MS."""
        accepted_status = kwargs.get("accepted_status", [requests.codes.ok, requests.codes.no_content])
        adding_error_handling = []
        for error_code in [requests.codes.forbidden]:
            if error_code not in accepted_status:
                accepted_status.append(error_code)
                adding_error_handling.append(error_code)
        kwargs["accepted_status"] = accepted_status

        time_start = time.time()
        timeout = 60
        retry_count = 0
        while (time.time() - time_start) < timeout:
            response = super().request(method, url, *args, **kwargs)
            if response.status_code in adding_error_handling:
                if retry_count > 0:
                    break
                if response.status_code == requests.codes.forbidden:
                    self._log.debug("No valid login, trying to login on MS: %s", response.text)
                    self.login()
                    retry_count += 1
                else:
                    self._log.warning(
                        "%s: %s failed with exit code %s [%d], retry executed in 10 sec",
                        method.upper(),
                        url,
                        responses[response.status_code],
                        response.status_code,
                    )
                    time.sleep(10)
                    retry_count += 1
            else:
                break

        if not time.time() - time_start < timeout or retry_count > 0:  # If login did not work (timeouted out)
            for error_code in adding_error_handling:
                del accepted_status[accepted_status.index(error_code)]
            super()._check_response(method, response, accepted_status)
        return response

    def login(self, user: str = "", password: str = "") -> type:
        """Login on MS."""
        self._log.debug("login on MS")
        if self._is_logged_in:
            self.logout()  # close old session before logging in again

        self.usr = user or self.usr
        self.psw = password or self.psw

        if not self.usr or not self.psw:
            msg = "No username/password provided for MS login"
            raise ValueError(msg)

        response = self.post(
            url="/auth/login",
            json={"identity": self.usr, "secret": self.psw},
            accepted_status=[requests.codes.ok],
        )
        self._add_header["sessionid"] = f"{response.headers['sessionId']}"
        self._is_logged_in = True

        return response

    def logout(self):
        """Logout from MS."""
        self._log.debug("Logout from MS")
        if self.version_smaller_than("2.10.0"):
            response = self.get("/auth/logout", accepted_status=[requests.codes.ok, requests.codes.forbidden])
        response = self.get(
            "/auth/logout", accepted_status=[requests.codes.no_content, requests.codes.forbidden]
        )
        self._is_logged_in = False
        return response
