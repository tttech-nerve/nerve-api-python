[back (nerve_lib)](./index.md)

Module nerve_lib.manage_volumes
===============================
Manage Docker volumes and unused images on nodes from MS.

This module provides the DockerVolumes class for managing Docker volumes.

Classes
-------

`DockerVolumes(ms_handle: type)`
:   Handle to Docker volumes on node from MS.
    
    Parameters
    ----------
    ms_handle : type
        handle to manage_workloads.Workloads object.

    ### Methods

    `check_export_status(self, dut_serial, volume_name, retry_timeout=60)`
    :   Check the status of the export operation with improved error handling.

    `delete_all_volumes(self, dut_serial: str)`
    :   Delete all docker volumes on a node with improved error handling and logging.

    `delete_volume(self, dut_serial: type, volume_name: str)`
    :   Delete a Docker volume.
        
        Parameters
        ----------
        dut_serial: type
            reference to node serial number.
        volume_name: str
            docker volume name.
        Returns
        -------
        Response object from the MS API.

    `export_volume_data_ms(self, dut_serial, volume_name, export_timeout=30)`
    :   Export data from a volume with improved error handling.

    `get_volumes(self, dut_serial: type)`
    :   Get all Docker volumes on a node.
        
        Parameters
        ----------
        dut_serial : type
            reference to node serial number.
        Returns
        -------
        Response object from the MS API.

    `import_volume_data_ms(self, dut_serial, volume_name, file, import_timeout=30)`
    :   Import data to a volume with improved error handling.