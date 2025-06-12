[back (nerve_lib)](./index.md)

Module nerve_lib.manage_registry
================================
Manage Docker registry images on nodes from MS.
This module provides the InternalRegistry class for managing Docker
registry images and their tags.
It includes methods for retrieving images, checking their status,
deleting tags, and more.

Classes
-------

`InternalRegistry(ms_handle: type)`
:   Handle to internal registry of a MS.
    
    Parameters
    ----------
    owner : type
        handle to manage_workloads.Workloads object.
    workload_name : str
        selected workload name.
    version : str, optional
        selected workload version. If empty, the last version will be selected. The default is "".
    release_version : str, optional
        selected release version. If empty, the last version will be selected. The default is "".

    ### Methods

    `check_image_status(self, images: list[str] = [])`
    :   Check image status.
        
        Parameters
        ----------
        images : list[str]
            image name(s).
        
        Returns
        -------
        dict
            MS API response containing image status.

    `delete_image_tag(self, image: str, tag: str)`
    :   Delete image tag.
        
        Parameters
        ----------
        image : str
            image name.
        tag : str
            tag name.

    `get_image_tags(self, image: str)`
    :   Get image tags.
        
        Parameters
        ----------
        image : str
            image name.
        
        Returns
        -------
        dict
            MS API response containing image tags.

    `get_registry_images(self, last: str = '', limit: int = 0)`
    :   Get registry images.
        
        Parameters
        ----------
        last : str, optional
            The starting point for fetching registry images. Default is "".
        limit : int, optional
            The maximum number of images to retrieve. Default is 0.
        
        Returns
        -------
        dict
            MS API response containing registry images.