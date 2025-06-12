[back (nerve_lib)](./index.md)

Module nerve_lib.general_utils
==============================
Provides several classes to access a node or a management system.

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

Functions
---------

`setup_logging(compact=False)`
:   Create logging output configuration if it does not exist already.
    
    Usable ENV Vars:
        - LOGGING_LEVEL: Default log-level to be used, if not defined, level INFO is selected.
        - DEBUG_LOG_FILE: file name of a log file which will contain all logs including debug output

Classes
-------

`CheckStatusCodeError(message: str, status_code: int, response_text: str)`
:   Error for Invalid response status codes.
    
    msg.status_code: received status_code
    msg.value: string error message

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException

`MSHandle(ms_url: str, user: str = '', password: str = '')`
:   Connect to a MS and handle requests.
    
    Parameters
    ----------
    ms_url : str
        MS URL to connect to, e.g. test.nerve.cloud.
    user : str, optional
        username to login on MS. The default is ENV-var MS_USR.
    password : str, optional
        password to logon on MS. The default is ENV-var MS_PSW.

    ### Ancestors (in MRO)

    * nerve_lib.general_utils.RequestGeneral
    * requests.sessions.Session
    * requests.sessions.SessionRedirectMixin

    ### Instance variables

    `version: str`
    :   Get the version of the MS.
        
        Returns
        -------
        str
            version of the MS.

    ### Methods

    `login(self) ‑> type`
    :   Login on MS.

    `logout(self)`
    :   Logout from MS.

    `request(self, method, url, *args, **kwargs) ‑> type`
    :   Execute a request on the MS.

    `version_smaller_than(self, version: str) ‑> bool`
    :   Check if the MS version is smaller than the provided version.
        
        Parameters
        ----------
        version : str
            version to be checked.
        
        Returns
        -------
        bool
            True if the MS version is smaller than the provided version.

`ManageSshTunnel(user: str | None = None, password: str | None = None, log: type | None = None)`
:   Manage SSH Tunnels required to access e.g. localUI of a node.
    
    Parameters
    ----------
    user : str, optional
        ssh user to connect to the device. The default is None.
    password : str, optional
        ssh password to connect to the device. The default is None.
    log : type, optional
        handle of logging.getLogger(...). The default is None.

    ### Methods

    `create_tunnel(self, ip_address, remote_bind: tuple[str, int], local_port: int | None = None) ‑> type`
    :   Create a specific ssh-tunnel to a node.
        
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

    `refresh_tunnels(self) ‑> bool`
    :   Check if created tunnels are active and stop/start them in case they are not running.
        
        Returns
        -------
        bool
            If false: Refreshing tunnel failed, a warning is printed in addition.

    `remove_tunnel(self, local_port: int) ‑> None`
    :   Remove a tunnel and close the connection.
        
        Parameters
        ----------
        local_bind : tuple[str, int]
            local bind information (ip-address, port).

`NodeHandle(ip_addr: str, user: str | None = None, password: str | None = None, ssh_user: str | None = None, ssh_password: str | None = None, api_path: str = '/', serial_number: str | None = None, local_ui_port: int = 3333, local_ui_ip_addr: str = '172.20.2.1', local_bind_port: int = 3333)`
:   Node requests and ssh connection management.
    
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

    ### Ancestors (in MRO)

    * nerve_lib.general_utils.RequestGeneral
    * requests.sessions.Session
    * requests.sessions.SessionRedirectMixin

    ### Methods

    `create_tunnel_node(self)`
    :   Create a ssh-tunnel to the localUI of a node.

    `login(self)`
    :   Login to Node.

    `logout(self)`
    :   Logout from Node.

    `request(self, method, url, *args, **kwargs) ‑> type`
    :   Execute a request on the node.

`RequestGeneral(url: str, api_path: str, log: type)`
:   Manage Requests to Nodes and MS.
    
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

    ### Ancestors (in MRO)

    * requests.sessions.Session
    * requests.sessions.SessionRedirectMixin

    ### Descendants

    * nerve_lib.general_utils.MSHandle
    * nerve_lib.general_utils.NodeHandle

    ### Methods

    `request(self, method: str, url: str, accepted_status: list = [200, 204], content_type: str = 'application/json', **kwargs) ‑> type`
    :   Overwrite default request function.
        
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

`SshGeneral(ip_addr: str, user: str = '', password: str = '')`
:   Allow to access a device over ssh and execute commands.
    
    Parameters
    ----------
    ip_addr : str
        IP address of the device.
    user : str
        ssh username to login.
    password : str
        ssh password to login.

    ### Methods

    `check_port_open(self, port: int) ‑> bool`
    :   Test is port open on Node, e.g. port 22 (SSH).
        
        Parameters
        ----------
        port : int
            port to be checked.
        
        Returns
        -------
        bool
            validates if port is open.

    `connect(self, timeout: float = 30.0, key: str | None = None, compress: bool = False) ‑> type`
    :   Create an ssh connection to a device.
        
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

    `copy(self, file_name: str, file_path: str = 'images/', max_retries: int = 3) ‑> bool`
    :   Copy a file via SCP to a device.
        
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

    `execute(self, cmd: str, timeout: float = 30.0, ssh: type | None = None, as_sudo: bool = False, compress: bool = False, sudo_psw: str | None = None) ‑> str`
    :   Execute a ssh command on a device.
        
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

    `reboot(self)`
    :   Execute a reboot command over ssh on a device.