[back (nerve_lib)](./index.md)

Module nerve_lib.manage_dna
===========================
Manage DNA releated function on a Node or MS.

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

Classes
-------

`DNACommon(handle, base_url: str, log: type)`
:   Common class for localUI and MS based DNA handling.
    
    Parameters
    ----------
    handle : type
        node or ms handle.
    base_url : str
        depending on node or ms handle, the base_url must be defined correct.
    log : type
        used logger to output logging data.

    ### Descendants

    * nerve_lib.manage_dna.LocalDNA
    * nerve_lib.manage_dna.MSDNA
    * nerve_lib.manage_dna.ServiceOSDNACommon

    ### Methods

    `cancel_target(self) ‑> dict`
    :   Same as patch_target_cancel.

    `get_current(self) ‑> dict`
    :   Get the current DNA configuration.
        
        Returns
        -------
        dict
            current configuration.

    `get_status(self) ‑> dict`
    :   Get the DNA configuration status.
        
        Returns
        -------
        dict
            configuration status.

    `get_target(self) ‑> dict`
    :   Get the target DNA configuration.
        
        Returns
        -------
        dict
            target configuration.

    `patch_target_cancel(self) ‑> dict`
    :   Cancle an ongoing configuration.
        
        Returns
        -------
        dict
            response of the command.

    `put_target(self, config_file, continue_after_restart: bool = False, restart_all_wl: bool = False, remove_images: bool = True, sign_file: bool = False) ‑> dict`
    :   Put new target configuration to the device.
        
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

    `put_target_re_apply(self) ‑> dict`
    :   Reaply the target configuration.
        
        Returns
        -------
        dict
            response of the command.

    `reapply_target(self) ‑> dict`
    :   Same as put_target_re_apply.

`LocalDNA(node_handle: type)`
:   Manage the DNA of a device directly using localUI API comamnds.
    
    Parameters
    ----------
    node_handle : type
        handle to the node 'nerve_lib.general_utils.NodeHandle(...)'.

    ### Ancestors (in MRO)

    * nerve_lib.manage_dna.DNACommon

`LocalUIDNAServiceOS(node_handle: type)`
:   Manage Service OS DNA of a device via Local UI API commands.
    
    Parameters
    ----------
    node_handle : type
        Handle to the node (e.g. nerve_lib.general_utils.NodeHandle(...))

    ### Ancestors (in MRO)

    * nerve_lib.manage_dna.ServiceOSDNACommon
    * nerve_lib.manage_dna.DNACommon

`MSDNA(ms_handle: type, node_serial_number: str)`
:   Management system API commands to handle DNA of a device.
    
    Parameters
    ----------
    ms_handle : type
        handle to the MS 'nerve_lib.general_utils.MSHandle(...)'.
    node_serial_number : str
        Serial number of the connected node to execute the DNA functions with.

    ### Ancestors (in MRO)

    * nerve_lib.manage_dna.DNACommon

`ServiceOSDNA(ms_handle: type, node_serial_number: str)`
:   Management system API commands to handle Service OS DNA of a device.
    
    Parameters
    ----------
    ms_handle : type
        handle to the MS 'nerve_lib.general_utils.MSHandle(...)'.
    node_serial_number : str
        Serial number of the connected node to execute the Service OS DNA functions with.

    ### Ancestors (in MRO)

    * nerve_lib.manage_dna.ServiceOSDNACommon
    * nerve_lib.manage_dna.DNACommon

`ServiceOSDNACommon(handle, base_url: str, log: type)`
:   Common class for localUI and MS based Service OS DNA handling.

    ### Ancestors (in MRO)

    * nerve_lib.manage_dna.DNACommon

    ### Descendants

    * nerve_lib.manage_dna.LocalUIDNAServiceOS
    * nerve_lib.manage_dna.ServiceOSDNA

    ### Methods

    `put_target(self, config_dict: dict) ‑> dict`
    :   Apply target Service OS DNA configuration using a configuration dict.
        
        Parameters
        ----------
        config_dict : dict
            Configuration dictionary to upload as YAML.
        
        Returns
        -------
        dict
            Response from the device.