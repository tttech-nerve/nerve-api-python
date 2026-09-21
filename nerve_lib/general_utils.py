# Copyright (c) 2026 TTTech Industrial Automation AG.
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
import select
import socket
import socketserver
import threading
import time
import weakref
from http.client import responses
from urllib.parse import urljoin

import paramiko
import requests
import urllib3
from requests_toolbelt import MultipartEncoder
from scp import SCPClient
from scp import SCPException

urllib3.disable_warnings()


def setup_logging(compact=False):
    """Create logging output configuration if it does not exist already.

    Usable ENV Vars:
        - LOGGING_LEVEL: Default log-level to be used, if not defined, level INFO is selected.
        - DEBUG_LOG_FILE: file name of a log file which will contain all logs including debug output
    """
    # remove all handlers which are NOTSET
    logging.root.handlers = [
        handler
        for handler in logging.root.handlers
        if not (
            handler.level == logging.NOTSET
            and isinstance(handler, (logging.StreamHandler, logging.FileHandler))
        )
    ]

    # add stream handler
    stream_handler_configured = any(
        isinstance(handler, logging.StreamHandler) for handler in logging.root.handlers
    )
    if not stream_handler_configured:
        stream_handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "{levelname:<7} {name:<20.20} :: {message}"
            if compact
            else "{levelname:<7} {name:<35.35} {filename:>20.20}-{lineno:<4} :: {message}",
            style="{",
        )
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(os.environ.get("LOGGING_LEVEL", "INFO").upper())
        logging.getLogger().addHandler(stream_handler)
        logging.getLogger().setLevel("NOTSET")  # Set root-logger level

        logging.getLogger("paramiko").setLevel(logging.WARNING)
        logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)  # Suppress paramiko debug messages
        logging.getLogger("pykeepass").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    # add file handler
    if os.environ.get("DEBUG_LOG_FILE", ""):
        file_handler_configured = any(
            isinstance(handler, logging.FileHandler) for handler in logging.root.handlers
        )
        if not file_handler_configured:
            file_handler = logging.FileHandler(os.environ.get("DEBUG_LOG_FILE"))
            formatter = logging.Formatter(
                "{asctime} {levelname:<7} {name:<25} {filename:>25.25}-{lineno:<4} :: {message}",
                style="{",
            )
            file_handler.setFormatter(formatter)
            file_handler.setLevel(logging.DEBUG)
            logging.getLogger().addHandler(file_handler)


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


class _ParamikoForwardServer(socketserver.ThreadingTCPServer):
    """TCP server used for Paramiko local port forwarding."""

    daemon_threads = True
    allow_reuse_address = True


class _ParamikoForwardHandler(socketserver.BaseRequestHandler):
    """Forward a single local TCP connection over a Paramiko transport."""

    ssh_transport: paramiko.Transport
    remote_bind_address: tuple[str, int]
    log: logging.Logger

    def handle(self) -> None:
        channel = None
        try:
            channel = self._open_channel()
            if channel is None:
                return
            self._forward_channel(channel)
        except (OSError, EOFError, paramiko.SSHException) as ex_msg:
            self.log.debug("Tunnel forwarding connection failed: %s", ex_msg)
        finally:
            if channel is not None:
                channel.close()
            self.request.close()

    def _open_channel(self):
        remote_host, remote_port = self.remote_bind_address
        try:
            channel = self.ssh_transport.open_channel(
                "direct-tcpip",
                (remote_host, remote_port),
                self.request.getpeername(),
            )
        except paramiko.SSHException as ex_msg:
            self.log.debug("Could not open tunnel channel to %s:%s: %s", remote_host, remote_port, ex_msg)
            return None
        if channel is None:
            self.log.debug("Could not open tunnel channel to %s:%s", remote_host, remote_port)
        return channel

    def _forward_channel(self, channel) -> None:
        while True:
            readable, _, _ = select.select([self.request, channel], [], [])
            if self.request in readable and not self._send_to_channel(channel):
                break
            if channel in readable and not self._send_to_request(channel):
                break

    def _send_to_channel(self, channel) -> bool:
        data = self.request.recv(1024)
        if not data:
            return False
        channel.sendall(data)
        return True

    def _send_to_request(self, channel) -> bool:
        data = channel.recv(1024)
        if not data:
            return False
        self.request.sendall(data)
        return True


class _ParamikoTunnelHandle:
    """Lightweight wrapper around a Paramiko local forward."""

    def __init__(
        self,
        ssh_host: str,
        ssh_port: int,
        remote_bind: tuple[str, int],
        local_bind: tuple[str, int],
        ssh_client: paramiko.SSHClient,
        forwarder: _ParamikoForwardServer,
        forwarder_thread: threading.Thread,
        log: logging.Logger,
        ssh_user: str | None = None,
        ssh_password: str | None = None,
    ) -> None:
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.remote_bind_address = remote_bind
        self.local_bind_address = local_bind
        self.ssh_user = ssh_user
        self.ssh_password = ssh_password
        self._ssh_client = ssh_client
        self._forwarder = forwarder
        self._forwarder_thread = forwarder_thread
        self._log = log

    @property
    def is_alive(self) -> bool:
        if not self._forwarder_thread.is_alive():
            return False
        return self._probe_ssh_connection()

    @property
    def tunnel_is_up(self) -> dict:
        return {self.local_bind_address: self.is_alive}

    def stop(self) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._forwarder.shutdown()
            self._forwarder.server_close()
        except (RuntimeError, OSError) as ex_msg:
            self._log.debug("Exception while closing tunnel forwarder: %s", ex_msg)
        try:
            self._ssh_client.close()
        except (RuntimeError, OSError, paramiko.SSHException) as ex_msg:
            self._log.debug("Exception while closing tunnel SSH connection: %s", ex_msg)

    def _probe_ssh_connection(self) -> bool:
        """Check that the underlying ssh transport is still usable.

        Relies on the transport keepalive to detect a dead peer and uses a
        lightweight ignore-message write to surface a broken socket without
        opening a new session channel on every check.
        """
        transport = self._ssh_client.get_transport()
        if transport is None or not transport.is_active():
            return False
        try:
            transport.send_ignore()
        except (OSError, EOFError, paramiko.SSHException) as ex_msg:
            self._log.debug(
                "SSH tunnel health probe failed for %s:%s -> %s:%s: %s",
                self.ssh_host,
                self.ssh_port,
                self.remote_bind_address[0],
                self.remote_bind_address[1],
                ex_msg,
            )
            return False

        return True


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
    log : logging.Logger, optional
        Logger to use for logging. If not provided, a default logger will be created.
    """

    def __init__(
        self, ip_addr: str, user: str = "", password: str = "", logger: logging.Logger | None = None
    ):  # nosec B107
        setup_logging()
        self.ip_addr = ip_addr
        self._ssh_usr = user or os.environ.get("SSH_USR")
        self._ssh_psw = password or os.environ.get("SSH_PSW")
        self._log = logger.getChild("SSH") if logger else logging.getLogger(f"SSH-{ip_addr}")
        self._ssh_connection = None

    def __enter__(self):
        """Enter function when using with statement."""
        return self

    def __exit__(self, *args):
        """Exit function when using with statement."""
        if self._ssh_connection:
            self._ssh_connection.close()

    def connect(self, timeout: float = 30.0, key: str | None = None, compress: bool = False) -> type:
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
        if (
            self._ssh_connection
            and self._ssh_connection.get_transport()
            and self._ssh_connection.get_transport().is_active()
        ):
            return self._ssh_connection
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
        self._ssh_connection = ssh
        return ssh

    def execute(
        self,
        cmd: str,
        timeout: float = 30.0,
        ssh: type | None = None,
        as_sudo: bool = False,
        compress: bool = False,
        sudo_psw: str | None = None,
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
            cmd = f'echo "{sudo_psw}" | sudo -S {cmd}'
        output = ""
        ssh_ = ssh or self.connect(timeout, compress=compress)

        _stdin, stdout, stderr = ssh_.exec_command(cmd, timeout=timeout)
        output += "".join(stdout.readlines())
        output += "".join(stderr.readlines())
        return output.replace("[sudo] password for admin: ", "")

    def __del__(self):
        """Destructor to ensure that the ssh connection is closed when the object is deleted."""
        if self._ssh_connection:
            self._ssh_connection.close()

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
        except OSError:
            return False
        finally:
            s.close()
        return True

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
            except (FileNotFoundError, OSError, SCPException, paramiko.SSHException) as ex_msg:
                self._log.error("Failed to copy file to device: %s", ex_msg)
                if retry_count >= max_retries:
                    return False
                retry_count += 1
                self._log.info("copy file failed, executing retry in 20 sec...")
                time.sleep(20)
            else:
                return True


class ManageSshTunnel:
    """Manage SSH Tunnels required to access e.g. localUI of a node.

    Parameters
    ----------
    user : str, optional
        ssh user to connect to the device. The default is None.
    password : str, optional
        ssh password to connect to the device. The default is None.
    log : logging.Logger, optional
        handle of logging.getLogger(...). The default is None.
    """

    _shared_instance: "ManageSshTunnel | None" = None
    _shared_instance_lock = threading.Lock()

    def __init__(
        self, user: str | None = None, password: str | None = None, log: logging.Logger | None = None
    ):
        setup_logging()
        self._log = log.getChild("SSH-Tunnel") if log else logging.getLogger("SSH-Tunnel")
        self._ssh_usr = user or os.environ.get("SSH_USR")
        self._ssh_psw = password or os.environ.get("SSH_PSW")
        self._tunnels = {}
        self._tunnel_refs = {}
        self._lock = threading.Lock()
        self._finalizer_handle = weakref.finalize(
            self,
            self._cleanup,
            self._log,
            self._tunnels,
        )
        self._finalizer = self._manual_cleanup

    def __enter__(self):
        """Enter function when using with statement."""
        return self

    def __exit__(self, *args):
        """Exit function when using with statement."""
        if hasattr(self, "_finalizer"):
            self._finalizer()

    @classmethod
    def get_shared(
        cls,
        user: str | None = None,
        password: str | None = None,
        log: logging.Logger | None = None,
    ) -> "ManageSshTunnel":
        """Return a process-wide shared tunnel manager.

        Multiple node handles reuse a single manager so that tunnels sharing the
        same connection path are reference-counted and only closed once every
        user has released them.
        """
        with cls._shared_instance_lock:
            if cls._shared_instance is None:
                cls._shared_instance = cls(user=user, password=password, log=log)
            return cls._shared_instance

    @staticmethod
    def _cleanup(log, tunnels):
        """Safely cleanup class.

        If the class shall be manually cleaned, call this function:

        >>> ssh_tunnel._finalizer()
        """
        for tunnel_key, tunnel in list(tunnels.items()):
            log.debug("Closing Tunnel %s", tunnel_key)
            try:
                tunnel.close()
            except (SSHTunnelError, RuntimeError, OSError, paramiko.SSHException):
                log.warning("Could not close tunnel %s cleanly", tunnel_key)
        tunnels.clear()

    def _reset_finalizer(self):
        self._finalizer_handle = weakref.finalize(
            self,
            self._cleanup,
            self._log,
            self._tunnels,
        )
        self._finalizer = self._manual_cleanup

    def _manual_cleanup(self):
        if self._finalizer_handle.alive:
            self._finalizer_handle()
        self._reset_finalizer()

    @staticmethod
    def _is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
        """Check whether a TCP endpoint accepts connections.

        Used as a fast pre-flight probe before opening an ssh-tunnel so that an
        unreachable node (e.g. SSH port closed/refused) can be reported clearly.

        Parameters
        ----------
        host : str
            target ip-address or hostname.
        port : int
            target tcp port.
        timeout : float, optional
            connection timeout in seconds. The default is 3.0.

        Returns
        -------
        bool
            True if the port accepts a connection, False otherwise.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, int(port)))
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            return False
        finally:
            sock.close()
        return True

    # keepalive interval (seconds) to keep the ssh-tunnel connection open through idle periods
    _KEEPALIVE_INTERVAL = 15

    def _connect_ssh(
        self, ssh_host: str, ssh_port: int, user: str | None = None, password: str | None = None
    ) -> paramiko.SSHClient:
        """Open a dedicated Paramiko connection for a tunnel with keepalive enabled.

        The connection is owned by the tunnel handle, so it must not be created via a
        throwaway wrapper whose destructor would close it again.

        Parameters
        ----------
        ssh_host : str
            target ip-address or hostname.
        ssh_port : int
            target ssh port.
        user : str, optional
            ssh username. Defaults to the manager default when not provided.
        password : str, optional
            ssh password. Defaults to the manager default when not provided.

        Returns
        -------
        paramiko.SSHClient
            a connected client with an active transport and keepalive enabled.
        """
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(
                ssh_host,
                port=ssh_port,
                username=user if user is not None else self._ssh_usr,
                password=password if password is not None else self._ssh_psw,
                timeout=10,
                banner_timeout=10,
                auth_timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
        except (OSError, paramiko.SSHException) as ex_msg:
            ssh_client.close()
            msg = f"Could not open ssh connection to {ssh_host}:{ssh_port}: {ex_msg}"
            raise SSHTunnelError(msg) from ex_msg

        transport = ssh_client.get_transport()
        if transport is None or not transport.is_active():
            ssh_client.close()
            msg = f"SSH connection to {ssh_host}:{ssh_port} is not active"
            raise SSHTunnelError(msg)
        transport.set_keepalive(self._KEEPALIVE_INTERVAL)
        return ssh_client

    def _open_tunnel(
        self,
        ssh_host: str,
        ssh_port: int,
        remote_bind: tuple[str, int],
        local_bind: tuple[str, int],
        user: str | None = None,
        password: str | None = None,
    ):
        ssh_user = user if user is not None else self._ssh_usr
        ssh_password = password if password is not None else self._ssh_psw
        ssh_client = self._connect_ssh(ssh_host, ssh_port, ssh_user, ssh_password)
        transport = ssh_client.get_transport()

        handler = type(
            "ParamikoForwardHandler",
            (_ParamikoForwardHandler,),
            {
                "ssh_transport": transport,
                "remote_bind_address": remote_bind,
                "log": self._log,
            },
        )
        try:
            forwarder = _ParamikoForwardServer(local_bind, handler)
        except OSError as ex_msg:
            ssh_client.close()
            msg = f"Could not bind local forward socket on {local_bind[0]}:{local_bind[1]}: {ex_msg}"
            raise SSHTunnelError(msg) from ex_msg
        forwarder_thread = threading.Thread(
            target=forwarder.serve_forever,
            name=f"ParamikoTunnel-{local_bind[1]}",
            daemon=True,
        )
        forwarder_thread.start()
        return _ParamikoTunnelHandle(
            ssh_host,
            ssh_port,
            remote_bind,
            local_bind,
            ssh_client,
            forwarder,
            forwarder_thread,
            self._log,
            ssh_user,
            ssh_password,
        )

    @staticmethod
    def _build_endpoints(
        ip_address, remote_bind: tuple[str, int], local_port: int | None
    ) -> tuple[str, str, int, tuple[str, int], tuple[str, int]]:
        """Normalize connection parameters and build the unique tunnel key.

        Returns
        -------
        tuple
            (tunnel_key, ssh_host, ssh_port, remote_bind, local_bind).
        """
        if not local_port:
            local_port = remote_bind[1]
        if isinstance(ip_address, tuple):
            ssh_host = str(ip_address[0])
            ssh_port = int(ip_address[1])
        else:
            ssh_host = str(ip_address)
            ssh_port = 22
        remote_bind = (str(remote_bind[0]), int(remote_bind[1]))
        local_bind = ("127.0.0.1", int(local_port))
        tunnel_key = f"{ssh_host}:{ssh_port}:: {remote_bind[0]}:{remote_bind[1]} -> {local_bind[1]}"
        return tunnel_key, ssh_host, ssh_port, remote_bind, local_bind

    def _ensure_tunnel(
        self,
        tunnel_key: str,
        ssh_host: str,
        ssh_port: int,
        remote_bind: tuple[str, int],
        local_bind: tuple[str, int],
        user: str | None = None,
        password: str | None = None,
    ):
        """Return an alive tunnel for the given path, creating it if necessary.

        This does not modify the reference count; it only guarantees that an open
        tunnel handle is stored for the connection path.
        """
        with self._lock:
            existing_tunnel = self._tunnels.get(tunnel_key)
            if existing_tunnel and existing_tunnel.is_alive:
                self._log.debug("Tunnel %s existed, nothing todo", tunnel_key)
                return existing_tunnel
        self._log.debug("Creating ssh tunnel for %s", tunnel_key)

        # Pre-flight probe: if the node's SSH port is not reachable, report it clearly.
        if not self._is_port_open(ssh_host, ssh_port):
            self._log.error(
                "Could not establish tunnel %s: SSH port %s on %s is not reachable "
                "(node offline, SSH service down, or blocked by firewall)",
                tunnel_key,
                ssh_port,
                ssh_host,
            )
            return None

        try:
            tunnel = self._open_tunnel(ssh_host, ssh_port, remote_bind, local_bind, user, password)
        except (RuntimeError, OSError, SSHTunnelError, paramiko.SSHException) as ex_msg:
            self._log.error(
                "Could not establish tunnel %s (SSH %s:%s): %s",
                tunnel_key,
                ssh_host,
                ssh_port,
                ex_msg,
            )
            return None

        with self._lock:
            self._tunnels[tunnel_key] = tunnel
        self._log.debug("- is ssh tunnel alive?: %s", tunnel.is_alive)
        if tunnel.is_alive:
            return tunnel

        self._log.error("Could not establish tunnel %s, health probe failed", tunnel_key)
        return None

    def create_tunnel(
        self,
        ip_address,
        remote_bind: tuple[str, int],
        local_port: int | None = None,
        user: str | None = None,
        password: str | None = None,
    ) -> type:
        """Create a specific ssh-tunnel to a node.

        Example:

        >>> ssh_tunnel = ManageSshTunnel(user, password, logging.getLogger("CustomName"))
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
        tunnel_key, ssh_host, ssh_port, remote_bind, local_bind = self._build_endpoints(
            ip_address, remote_bind, local_port
        )

        tunnel = self._ensure_tunnel(tunnel_key, ssh_host, ssh_port, remote_bind, local_bind, user, password)
        if tunnel is None:
            return None

        # reference-count the connection path so shared tunnels stay open until
        # every acquirer released them again
        with self._lock:
            self._tunnel_refs[tunnel_key] = self._tunnel_refs.get(tunnel_key, 0) + 1
            ref_count = self._tunnel_refs[tunnel_key]
        self._log.debug("Tunnel %s acquired, reference count is now %d", tunnel_key, ref_count)
        return tunnel

    def remove_tunnel(self, local_port: int) -> None:
        """Remove a tunnel and close the connection.

        Parameters
        ----------
        local_bind : tuple[str, int]
            local bind information (ip-address, port).
        """
        with self._lock:
            tunnels_snapshot = list(self._tunnels.items())
        for tunnel_key, tunnel in tunnels_snapshot:
            if tunnel.local_bind_address == ("127.0.0.1", local_port):
                self._log.info("Removing tunnel %s", tunnel_key)
                try:
                    tunnel.close()
                except (SSHTunnelError, RuntimeError, OSError, paramiko.SSHException):
                    self._log.warning("Could not stop tunnel before removing")
                with self._lock:
                    self._tunnels.pop(tunnel_key, None)
                    self._tunnel_refs.pop(tunnel_key, None)
                return
        self._log.warning("Tunnel with local port %s does not exist", local_port)

    def release_tunnel(self, ip_address, remote_bind: tuple[str, int], local_port: int | None = None) -> None:
        """Release one reference to a tunnel and close it when unreferenced.

        Multiple node handles can share the same tunnel path. The tunnel is only
        closed once every handle that acquired it via ``create_tunnel`` has
        released it again.

        Parameters
        ----------
        ip_address : str | tuple[str, int]
            ip-address (or (ip, port) tuple) of the node the tunnel connects to.
        remote_bind : tuple[str, int]
            remote bind information (ip-address, port).
        local_port : int, optional
            local bind port. Defaults to the remote port when not provided.
        """
        tunnel_key, *_ = self._build_endpoints(ip_address, remote_bind, local_port)
        tunnel_to_close = None
        with self._lock:
            ref_count = self._tunnel_refs.get(tunnel_key, 0)
            if ref_count <= 1:
                self._tunnel_refs.pop(tunnel_key, None)
                tunnel_to_close = self._tunnels.pop(tunnel_key, None)
                remaining = 0
            else:
                remaining = ref_count - 1
                self._tunnel_refs[tunnel_key] = remaining

        if tunnel_to_close is not None:
            self._log.debug("Closing tunnel %s, last reference released", tunnel_key)
            try:
                tunnel_to_close.close()
            except (SSHTunnelError, RuntimeError, OSError, paramiko.SSHException):
                self._log.warning("Could not close tunnel %s cleanly on release", tunnel_key)
        else:
            self._log.debug("Tunnel %s still referenced (%d remaining)", tunnel_key, remaining)

    def refresh_tunnels(self) -> bool:
        """Check if created tunnels are active and stop/start them in case they are not running.

        Returns
        -------
        bool
            If false: Refreshing tunnel failed, a warning is printed in addition.

        """
        ret_val = True
        with self._lock:
            tunnels_snapshot = list(self._tunnels.items())

        for tunnel_key, tunnel in tunnels_snapshot:
            if tunnel.is_alive:
                continue

            self._log.info("Refreshing tunnel %s", tunnel_key)
            try:
                tunnel.close()
            except (SSHTunnelError, RuntimeError, OSError, paramiko.SSHException):
                self._log.warning("Could not stop tunnel before refresh")
            # keep tunnel metadata so subsequent refresh attempts can try again;
            # recreate without changing the reference count of the tunnel
            recreated = self._ensure_tunnel(
                tunnel_key,
                tunnel.ssh_host,
                tunnel.ssh_port,
                tunnel.remote_bind_address,
                tunnel.local_bind_address,
                tunnel.ssh_user,
                tunnel.ssh_password,
            )
            if recreated is None:
                self._log.warning("Could not refresh tunnel %s, device may be unreachable", tunnel_key)
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
    log : logging.Logger
        logging.getLogger(...) handle to be used.

    Returns
    -------
    None.

    """

    def __init__(self, url: str, api_path: str, log: logging.Logger):
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
        accepted_status: list[int] | None = None,
        content_type: str = "application/json",
        m_enc_data: dict | None = None,
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
        m_enc_data: dict, optional
            if m_enc_data is provided in the format {"field_name": (filename, file_data, content_type)},
            the request will be send as multipart/form-data with the provided data.
            In case of a retry, the m_enc_data handles will be reset to the beginning of the file data,
            to ensure that the full data is send in the retry.
            The default is None.
        **kwargs : TYPE
            additional key values as defined in requests.request object.

        Returns
        -------
        type
            requests.Response object.

        """
        if accepted_status is None:
            accepted_status = [requests.codes.ok, requests.codes.no_content]

        if "http" not in url:
            url = urljoin(self.api_url, url)
        if m_enc_data:
            for field_name, file_tuple in m_enc_data.items():
                if isinstance(file_tuple, tuple) and len(file_tuple) == 3:  # ruff:ignore[magic-value-comparison]
                    filename, file_data, file_content_type = file_tuple
                    if hasattr(file_data, "seekable") and file_data.seekable():
                        file_data.seek(0, os.SEEK_SET)
                        self._log.debug(
                            "Reset file data for field '%s' (%s) to the beginning", field_name, filename
                        )
                    m_enc_data[field_name] = (filename, file_data, file_content_type)
            m_enc = MultipartEncoder(fields=m_enc_data)
            kwargs["data"] = m_enc
            content_type = m_enc.content_type
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
        user: str | None = None,
        password: str | None = None,
        ssh_user: str | None = None,
        ssh_password: str | None = None,
        api_path: str = "/",
        serial_number: str | None = None,
        local_ui_port: int = 3333,
        local_ui_ip_addr: str = "172.20.2.1",
        local_bind_port: int = 3333,
        logger: logging.Logger | None = None,
    ):
        if local_ui_ip_addr == ip_addr and local_bind_port == local_ui_port:
            raise ValueError(
                "local_bind_port must be different from local_ui_port if local_ui_ip_addr is the same as ip_addr"
            )

        super().__init__(
            url=f"http://{ip_addr}:{local_ui_port}"
            if ip_addr == local_ui_ip_addr
            else f"http://127.0.0.1:{local_bind_port}",
            api_path=api_path,
            log=logger or logging.getLogger("Node"),
        )

        self._is_logged_in = False
        self.tunnel_node_created = False
        self.local_ui_port = local_ui_port
        self.local_ui_ip_addr = local_ui_ip_addr
        self.local_bind_port = local_bind_port
        self.ip_addr = ip_addr
        self.usr = user or os.environ.get("NODE_USR")
        self.psw = password or os.environ.get("NODE_PSW")
        self.serial_number = "unknown-sid"

        self.ssh = SshGeneral(ip_addr, user=ssh_user, password=ssh_password, logger=self._log)

        if isinstance(ip_addr, tuple):
            ip_addr = ip_addr[0]
        if ip_addr not in {"127.0.0.1", local_ui_ip_addr}:
            # share one tunnel manager across all node handles so tunnels using
            # the same connection path are reference-counted, not duplicated
            self.ssh_tunnel = ManageSshTunnel.get_shared(
                user=ssh_user,
                password=ssh_password,
                log=self._log,
            )

            try:
                self.serial_number = serial_number or json.loads(
                    self.ssh.execute("cat /etc/node_config.json"),
                ).get("serialId", "unknown-sid")
            except json.decoder.JSONDecodeError:
                pass

        else:
            self.tunnel_node_created = (
                True  # if node is local, no tunnel needs to be created, so we set this to true directly
            )

        self.__tunnels_created = []

        self._finalizer = weakref.finalize(self, self._cleanup, weakref.ref(self))

    def __enter__(self):
        """Enter function when using with statement."""
        return self

    def __exit__(self, *args):
        """Exit function when using with statement."""
        if hasattr(self, "_finalizer"):
            self._finalizer()

    def __del__(self):
        """Destructor to ensure that finalizer is called."""
        if hasattr(self, "_finalizer"):
            self._finalizer()

    @staticmethod
    def _cleanup(handle_ref):
        """Safely cleanup class.

        If the class shall be manually cleaned, call this function:

        >>> node._finalizer()
        """
        try:
            node = handle_ref()
        except (TypeError, ReferenceError):  # pragma: no cover - defensive
            node = None

        if node:
            if node._is_logged_in:
                try:
                    node.logout()  # close session before closing tunnels
                except SSHTunnelError:
                    node._log.warning(
                        "Could not logout cleanly during cleanup as tunnel to node cannot be established"
                    )
            node.release_tunnels()

    def create_tunnel(self, remote_bind=None, local_port=None):
        """Create a tunnel to a service of the node."""

        tunnel = self.ssh_tunnel.create_tunnel(
            self.ip_addr,
            remote_bind,
            local_port,
            user=self.ssh._ssh_usr,
            password=self.ssh._ssh_psw,
        )
        if tunnel is not None:
            self.__tunnels_created.append(tunnel)
        return tunnel

    def release_tunnels(self):
        """Release all tunnels which had been created by this node.

        After releasing, the localUI tunnel state is reset so a subsequent
        request re-establishes a fresh tunnel of the same kind.
        """
        for tunnel in self.__tunnels_created:
            self.ssh_tunnel.release_tunnel(
                self.ip_addr, tunnel.remote_bind_address, tunnel.local_bind_address[1]
            )
        self.__tunnels_created.clear()
        # only remote nodes use a tunnel; local nodes have no ssh_tunnel and must
        # keep tunnel_node_created=True so requests skip tunnel creation
        if hasattr(self, "ssh_tunnel"):
            self.tunnel_node_created = False

    def create_tunnel_node(self):
        """Create a ssh-tunnel to the localUI of a node."""
        if not self.tunnel_node_created:
            remote_bind = (self.local_ui_ip_addr, self.local_ui_port)
            tunnel = self.create_tunnel(remote_bind, self.local_bind_port)
            if tunnel is not None:
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
            except requests.exceptions.ConnectionError:
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
                        if hasattr(self, "ssh_tunnel") and self.ssh_tunnel:
                            self.ssh_tunnel.refresh_tunnels()
                        time.sleep(1)
                        continue

                self._log.error(
                    "Received a ConnectionError after %ssec when executing the command %s:%s",
                    int(time.time() - time_start),
                    method,
                    url,
                )
                raise

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
        self.ssh._ssh_usr = user
        self.ssh._ssh_psw = password

    def login(self, user: str = "", password: str = "", **kwargs):  # nosec B107
        """Login to Node.

        Allows to switch user when providing user/password, otherwise will use existing credentials.
        In case of a login error, e.g. max retry exceeded, the function will wait for 5 seconds and can be retried.

        Args:
            user (str, optional): username to login on Node. The default is "".
            password (str, optional): password to logon on Node. The default is "".
            **kwargs: Additional keyword arguments for future extensions.
        """
        self.usr = user or self.usr
        self.psw = password or self.psw

        self._log.debug("login with URL %s", self.url)
        if hasattr(self, "ssh_tunnel") and self.ssh_tunnel:
            self.ssh_tunnel.refresh_tunnels()

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
                accepted_status=[requests.codes.ok, requests.codes.unauthorized],
            )
            if response.status_code == requests.codes.unauthorized:
                super()._check_status_code("POST", response, [requests.codes.ok])  # will raise error

        except urllib3.exceptions.MaxRetryError:
            self._log.error("Login failed, max retry exceeded")
            time.sleep(5)
        except urllib3.exceptions.NewConnectionError:
            self._log.error("Login failed, can't establish new connection")
            time.sleep(5)
        except requests.exceptions.ConnectionError:
            self._log.error("Login failed, request ConnectionError is raised!")
            time.sleep(5)
        else:
            self._is_logged_in = True
            return response

    def logout(self):
        """Logout from Node."""
        self._log.debug("Logout from Node")
        try:
            response = self.get(
                "/api/auth/logout",
                accepted_status=[requests.codes.ok, requests.codes.no_content, requests.codes.unauthorized],
            )
        except urllib3.exceptions.MaxRetryError:
            self._log.error("Logout failed, max retry exceeded")
            time.sleep(5)
        except requests.exceptions.ConnectionError:
            self._log.error("Logout failed, request ConnectionError is raised!")
            time.sleep(5)
        else:
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
    access_token : str, optional
        access token to logon on MS. The default is ENV-var MS_ACCESS_TOKEN.
        If an access token is provided, the user and password will be ignored.
    """

    def __init__(self, ms_url: str, user: str = "", password: str = "", access_token: str = ""):  # nosec B107
        if ms_url.startswith("http"):
            self.ms_url = ms_url.split("://")[1]
            super().__init__(url=ms_url, api_path="/", log=logging.getLogger(f"MS-{ms_url}"))
        else:
            self.ms_url = ms_url
            super().__init__(url=f"https://{ms_url}", api_path="/", log=logging.getLogger(f"MS-{ms_url}"))
            self._log.debug("no http/https in URL, adding https://")

        self._finalizer = weakref.finalize(self, self._cleanup, weakref.ref(self))

        self.verify = False

        self.usr = user or os.environ.get("MS_USR", "")
        self.psw = password or os.environ.get("MS_PSW", "")
        self.access_token = access_token or os.environ.get("MS_ACCESS_TOKEN", "")

        self._is_logged_in = False
        self.__login_content = None
        if self.access_token:
            self._add_header["Authorization"] = f"Bearer {self.access_token}"
            self._is_logged_in = True

        self.__ms_version = None

    def __enter__(self):
        """Enter function when using with statement."""
        return self

    def __exit__(self, *args):
        """Exit function when using with statement."""
        if hasattr(self, "_finalizer"):
            self._finalizer()

    def __del__(self):
        """Destructor to ensure cleanup."""
        if hasattr(self, "_finalizer"):
            self._finalizer()

    @staticmethod
    def _cleanup(handle_ref):
        """Safely cleanup class.

        If the class shall be manually cleaned, call this function:

        >>> ms_handle._finalizer()
        """

        try:
            ms_handle = handle_ref()
        except (TypeError, ReferenceError):  # pragma: no cover - defensive
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

        if len(current_version) != 3:  # ruff:ignore[magic-value-comparison]
            return False  # e.g integration, master
        if len(comp_version) != 3:  # ruff:ignore[magic-value-comparison]
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
        for error_code in [requests.codes.forbidden, requests.codes.unauthorized]:
            if error_code not in accepted_status:
                accepted_status.append(error_code)
                adding_error_handling.append(error_code)
        kwargs["accepted_status"] = accepted_status

        time_start = time.time()
        timeout = 60
        retry_count = 0
        while (time.time() - time_start) < timeout:
            try:
                response = super().request(method, url, *args, **kwargs)
            except requests.exceptions.SSLError as ex_msg:
                if retry_count > 0:
                    raise
                self._log.warning(
                    "SSL error when accessing %s '%s', execute command again. Error message: %s",
                    method.upper(),
                    url,
                    ex_msg,
                )
                self.login()
                retry_count += 1
                continue
            if response.status_code in adding_error_handling:
                if retry_count > 0:
                    break
                if response.status_code in {requests.codes.forbidden, requests.codes.unauthorized}:
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

    def login(self, user: str = "", password: str = "", **kwargs) -> type:  # nosec B107
        """Login on MS.

        Allows to switch user when providing user/password, otherwise will use existing credentials.
        In case of a failed login, an error will be raised.

        Args:
            user (str, optional): username to login on MS. The default is ENV-var MS_USR.
            password (str, optional): password to logon on MS. The default is ENV-var MS_PSW.
            **kwargs: Additional keyword arguments for future extensions
        """

        if self.access_token:
            self._log.debug("Access token provided, no login required")
            return None

        if self._is_logged_in:
            self.logout()  # close old session before logging in again

        self._log.debug("login on MS")
        self.usr = user or self.usr
        self.psw = password or self.psw

        if (not self.usr or not self.psw) and not self.access_token:
            msg = "No username/password or access token provided for MS login"
            raise ValueError(msg)

        response = self.post(
            url="/auth/login",
            json={"identity": self.usr, "secret": self.psw},
            accepted_status=[
                requests.codes.ok,
                requests.codes.forbidden,
                requests.codes.unauthorized,
                requests.codes.not_acceptable,
            ],
        )
        if response.status_code in {
            requests.codes.forbidden,
            requests.codes.unauthorized,
            requests.codes.not_acceptable,
        }:
            self._is_logged_in = False
            super()._check_response("post", response, [requests.codes.ok])  # will raise error
        self._add_header["sessionid"] = f"{response.headers['sessionId']}"
        self.__login_content = response.json()
        self._is_logged_in = True

        return response

    @property
    def login_content(self):
        """Return the content of the last login response."""
        if self._is_logged_in and not self.access_token:
            return self.__login_content

        if not self.access_token:
            self.login()
            return self.__login_content

        raise ValueError("Cannot get login-content for token-based authentication")

    def logout(self):
        """Logout from MS."""
        if self.access_token:
            self._log.debug("Access token provided, no logout required")
            return None
        self._log.debug("Logout from MS")
        if self.version_smaller_than("2.10.0"):
            response = self.get("/auth/logout", accepted_status=[requests.codes.ok, requests.codes.forbidden])
        response = self.get(
            "/auth/logout",
            accepted_status=[
                requests.codes.no_content,
                requests.codes.forbidden,
                requests.codes.unauthorized,
            ],
        )
        self._is_logged_in = False
        return response
