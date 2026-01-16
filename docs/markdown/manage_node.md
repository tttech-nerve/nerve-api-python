[back (nerve_lib)](./index.md)

Module nerve_lib.manage_node
============================
Manage Node related operations from MS.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSNode
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     nodes = MSNode(ms_handle)
    >>>     nodes.get_nodes_by_name()
    <dict: node list from MS>

Classes
-------

`LocalNode(node_handle: type)`
:   Node related functions from LocalUI.

    ### Instance variables

    `version`
    :   Read node version.

    ### Methods

    `apply_node_configuration(self, config)`
    :   Apply a new node configuration by merging it with the current configuration.
        The new configuration is saved to a YAML file and sent to the node.
        
        Parameters
        ----------
            config : dict
                The new configuration to apply.
        
        Returns
        -------
            dict: The response from the node after applying the configuration.

    `auth_ms_on_node(self, ms_url: str, username: str, password: str)`
    :   Authenticate the node with the management system.

    `change_password(self, username, old_password, new_password)`
    :   Change the password for a user.

    `change_ssh_password(self, current_password, new_password)`
    :   SSH password changed.

    `check_management_system_url(self, ms_url: str)`
    :   Check if ms_url is valid.

    `codesys_download(self)`
    :   Download Codesys app archive.

    `create_schedule_vm_snapshot(self, workload_name, schedule_type, interval=1, day='Monday', day_time='', day_hours=1, day_minutes=1, vm_state='Current', time_zone='Europe/Belgrade', timezone_offset='+2')`
    :   Create a schedule for snapshots of a VM workload.
        
        schedule_type: str
            Type of schedule (Interval, Day)

    `create_vm_backup(self, workload_name, backup_name)`
    :   Create a backup of a VM workload over LocalUI.

    `create_vm_snapshot(self, workload_name, snapshot_name, description='')`
    :   Create a snapshot of a VM workload.

    `delete_schedule_vm_snapshot(self, workload_name)`
    :   Delete a schedule for snapshots of a VM workload.

    `delete_vm_snapshot(self, workload_name, snapshot_name)`
    :   Delete a snapshot of a VM workload.

    `deploy_vm_backup(self, backup_name)`
    :   Deploy a VM backup.

    `download_audit_log(self, destination_path: str) ‑> dict`
    :   Download current audit log file and archives created by logrotate, compressed in a zip archive.

    `edit_file(self, file_path, content, password)`
    :   Write content to a file on the device.

    `get_backup_list(self)`
    :   Read backup list for node.

    `get_custom_role_permissions(self)`
    :   Get list of all permissions for the custom role via /api/permissions/custom-role (GET).
        Returns: list of permission codes (strings)

    `get_deploy_backup_status(self, backup_id)`
    :   Get the state of a deployed backup.

    `get_info(self)`
    :   Read all node info elements.

    `get_network_configuration(self)`
    :   Get network configuration of all interface.

    `get_node_configuration(self)`
    :   Get the current node configuration.
        
        Returns
        -------
            dict: The current node configuration.

    `get_secure_id(self)`
    :   Read the secure id of a node.

    `get_vm_backup(self, backup_name)`
    :   Get VM backup details from repository.

    `get_vm_snapshot(self, workload_name)`
    :   Get a snapshot of a VM workload.

    `get_workload_list(self)`
    :   Read workload list for node.

    `local_node_change_resource_allocation(self, workload_name, cpu: int, memory)`
    :   Change resource allocation for a workload.

    `localui_apply_workload_configuration(self, device_id: int, zip_file: str, configurations) ‑> type`
    :   Add a workload configuration via localui.
        
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

    `node_configuration_apply_status(self)`
    :   Check the status of the node configuration application.
        
        Returns
        -------
            str: The status message of the node configuration application.

    `offboard_node_local_ui(self)`
    :   Offboarding node from the Local-UI.

    `rc_setting(self, approve: int)`
    :   Set remote connection approval settings.
        
                Valid values for 'approve' are:
        0 - Approval of connection set in Management System (default)
        1 - Always allow remote connections on this node
        2 - Request approval for every remote connection made to this node.

    `read_file(self, file_path)`
    :   Read the content of a file on the device.

    `reboot(self)`
    :   Reboot the node.

    `resolve_remote_connection(self, connection_uid: str, connection_request_uid: str, approved: bool)`
    :   Approve or reject a remote connection request.
        
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

    `restart_vm_backup(self, workload_name, backup_name)`
    :   Restart creating backup of a VM workload over LocalUI.

    `restore_vm_snapshot(self, workload_name, snapshot_name)`
    :   Restore a snapshot of a VM workload.

    `set_configuration(self, ms_url: str, node_name=None)`
    :   Set onboarding configuration to connect to a management system.
        
        Args:
        ms_url (str): The URL of the management system.
        node_name (str): The name of the node. Required for uki nerve-node devices.

    `set_critical_action(self, file_path, value)`
    :   Edit the critical actions file to change 'allow' to 'not allowed' or vice versa.
        
        Args:
            file_path (str): The path to the YAML file containing critical actions.
            value (str): The value to set ('allow' or 'not allowed').
        
        Returns
        -------
            str: The modified content of the YAML file as a string.

    `set_custom_role_permissions(self, permissions, patch_success_code=202)`
    :   Set list of permissions for the custom role via /api/permissions/custom-role (PATCH).
        permissions: list of permission codes (strings) ["AUTH:LOGOUT","AUTH:VIEW", ...
        Returns: response object

    `set_local_repository(self, protocol, repo_type, path, user=None, password=None, options='')`
    :   Set a local repository.

    `set_network_configuration(self, interface, allocation, ip_address='0.0.0.0', netmask='0.0.0.0', gateway='0.0.0.0', domain_names=[])`
    :   Set network configuration of an interface.
        
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

    `set_proxy(self, enabled, http_proxy, https_proxy, no_proxy='', user='', password='')`
    :   Manage Proxy settings on a node.

    `set_vm_backup(self, nfs_mountpoint: str, mount_options: str = 'rw,nolock')`
    :   Set or disable vm-backup.

    `terminate_connections(self, rc_list: list)`
    :   Terminate remote connections.
        
        Parameters
        ----------
        rc_list : list
            List of dictionaries containing connectionUid and connectionRequestUid.
        
        Returns
        -------
        dict
            Response from the API.

    `version_smaller_than(self, version: str) ‑> bool`
    :   Check if the node version is smaller than the provided version.
        
        Parameters
        ----------
        version : str
            version to be checked.
        
        Returns
        -------
        bool
            True if the MS version is smaller than the provided version.

    `vm_backup_status(self, workload_name, backup_name='')`
    :   Get status of backup creation of a VM workload.

`MSNode(ms_handle: type)`
:   Node related functions from MS.
    
    Parameters
    ----------
    ms_handle : type
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.

    ### Methods

    `Node(self, serial_number: str) ‑> type`
    :   Create handle for selected Node.
        
        Parameters
        ----------
        serial_number : str
            Serial number of the connected node.
        
        Returns
        -------
        type
            handle to the node.

    `create_node(self, name: str, model: str, secure_id: str, serial_number: str, labels: list = [], remote_connections: list = []) ‑> dict`
    :   Create new node on MS.
        
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

    `fetch_rtem_token_id(self, connection_uid: str, connection_request_uid: str) ‑> str`
    :   Get RTEM seesion ID.
        
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

    `get_active_remote_connections(self) ‑> dict`
    :   Read currently active remote connections on MS.
        
        Returns
        -------
        dict
            list of remote connections.

    `get_deploy_list(self, workload_id: str, version_id: str, node_name_filter: str) ‑> dict`
    :   Get list of nodes a workload can be deployed to.
        
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

    `get_nodes(self, serial_number: str | None = None) ‑> dict`
    :   Read node list of MS.
        
        Parameters
        ----------
        serial_number : str, optional
            Return only selected node information if paramter is set and matches to a node.
            The default is None.
        
        Returns
        -------
        dict
            Node list informatnion from MS API.

    `get_nodes_by_name(self, node_name_filter: str | None = None) ‑> dict`
    :   Read node list of MS filtered by name of the node.
        
        Parameters
        ----------
        node_name_filter : str, optional
            Return all nodes, containing the defined name. The default is None.
        
        Returns
        -------
        dict
            Node list informatnion from MS API.

    `remove_active_remote_connections(self, remote_ids: list | None = None) ‑> type`
    :   Remove established remote connections from MS.
        
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