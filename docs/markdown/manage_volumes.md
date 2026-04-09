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

    `import_volume_data(self, dut_serial, volume_name, file_path, import_timeout=30)`
    :   Import data to a volume with improved error handling.

`LocalDockerVolumes(node_handle)`
:   Handle Docker Volumes using localUI.

    ### Methods

    `delete_volume(self, volume_name)`
    :   Delete a Docker volume.
        
        Parameters
        ----------
        volume_name : str
            Name of the volume to be deleted.

    `export_volume_data(self, volume_name, file_path: str | None = None, export_timeout=30)`
    :   Export data from a volume.
        
        Parameters
        ----------
        volume_name : str
            Name of the volume.
        file_path : str | None
            Path to the file where the exported data will be saved. If None, the data will not be saved to a file.

    `get_volumes(self)`
    :   Get all Docker volumes on a node.

    `import_volume_data(self, volume_name, file_path, import_timeout=30)`
    :   Import data to a volume.
        
        Parameters
        ----------
        volume_name : str
            Name of the volume.
        file_path : str
            Path to the file to be imported.