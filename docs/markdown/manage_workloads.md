[back (nerve_lib)](./index.md)

Module nerve_lib.manage_workloads
=================================
Manage workloads on MS or LocalUi.

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

Classes
-------

`LocalWorkloads(node_handle: type)`
:   Manage workloads using localUI of a node.
    
    Parameters
    ----------
    node_handle : type
        handle to general_utils.MSNode.

    ### Methods

    `control(self, workload_name: str, command: str, remove_images: bool = True) ‑> None`
    :   Control the workload status.
        
        Parameters
        ----------
        workload_name : str
            Workload to be controlled.
        command : str
            Command can be one of START, STOP, SUSPEND, RESUME, RESTART, UNDEPLOY".

    `deploy_workload(self, file_paths: list[str], deploy_timeout: int = 300) ‑> type`
    :   Deploy workload on node directly.
        
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

    `export_volume_data(self, volume_name, export_timeout=30)`
    :   Import data to a volume.
        
        Parameters
        ----------
        volume_name : str
            Name of the volume.

    `get_workload_details(self, workload_name)`
    :   Read details of a deployed workload.

    `get_workload_list(self)`
    :   Get list of deployed workloads.

    `import_volume_data(self, volume_name, file, import_timeout=30)`
    :   Import data to a volume.
        
        Parameters
        ----------
        volume_name : str
            Name of the volume.
        file : str
            Path to the file to be imported.

    `undeploy(self, workload_name: str = '', remove_images: bool = True)`
    :   Undeploy workload.
        
        If no workload_name is defined, all workloads are undeployed.

`MSWorkloads(ms_handle: type)`
:   Manage workloads on a MS.
    
    Parameters
    ----------
    ms_handle : type
        handle of general_utils.MSHandle.

    ### Class variables

    `API_V1`
    :

    `API_V2`
    :

    `API_V3`
    :

    ### Methods

    `WorkloadVersion(self, workload_name: str, version: str = '', release_version: str = '')`
    :   Handle to specific workload of a MS.
        
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

    `check_for_deployment_state(self, deploy_name: str, state: str | None = None, timeout: int = 400, check_interval: int = 60) ‑> dict`
    :   Verify deployment state of a workload.
        
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

    `gen_workload_configuration(self, provision_type: str, file_paths: list[str] = '', wrkld_name: str = 'test_workload', wrkld_version_name: str = 'test_version', container_name: str = 'test_container', release_name: str = '', description: str = '', label: list = [], networks: list = ['bridge'], ports: list[dict] = [], docker_volumes: list[dict] = [], restart_on_config_update: bool = False, env_var: list[dict] = '', remote_connections: list[dict] = [], restart_policy: str = 'no', limit_cpus: str | None = None, limit_memory: dict | None = None, released: bool = False, auth_usr: str = '', auth_psw: str = '', vm_num_cpus: int = 1, vm_memory: dict = {'unit': 'MB', 'value': 700}, vm_snapshot: dict = {'enabled': False}, compose_dict: dict = {}, docker_config_volumes: list = [], api_version: int = 2, internal_docker_registry: bool = False) ‑> dict`
    :   Provision of Docker.
        
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

    `get_workloads_dict(self, read_versions=True, read_compose_details=True, compact_dict=True) ‑> dict`
    :   Read workloads list of MS.
        
        Returns
        -------
        dict
            dict of {workload-name: [version, release_version]}.

    `provision_compose_workload(self, payload: dict, update_workload: bool)`
    :   Create new docker-compose workload.
        
        Parameters
        ----------
        payload : dict
            workload description file, generated with Workloads.gen_workload_configuration(...).
        update_workload : bool
            Patch the workload with new paramters, if set to false, the workload will only be created, not changed.

    `provision_workload(self, payload: dict, file_paths: list[str] = [], api_version: int = 2, patch_version: bool = True, registry_download_timeout: int = 400) ‑> None`
    :   Provision a new workload to the MS.
        
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

    `validate_compose_content(self, content: dict, file_name: str = 'compose-file.yaml') ‑> dict`
    :   Validate if the content of a compose-file is valid.

`WorkloadDeployError(message: str)`
:   Error for Deployment failed.
    
    msg.value: string error message

    ### Ancestors (in MRO)

    * builtins.Exception
    * builtins.BaseException