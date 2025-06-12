# Copyright (c) 2025 TTTech Industrial Automation AG.
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

"""Manage Docker registry images on nodes from MS.
This module provides the InternalRegistry class for managing Docker
registry images and their tags.
It includes methods for retrieving images, checking their status,
deleting tags, and more.
"""

import requests


class InternalRegistry:
    """Handle to internal registry of a MS.

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
    """

    def __init__(self, ms_handle: type):
        self.ms = ms_handle

    def get_registry_images(self, last: str = "", limit: int = 0):
        """Get registry images.

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
        """
        payload = {}
        if last:
            payload["last"] = last
        if limit > 0:
            payload["limit"] = limit

        return self.ms.post(
            "nerve/registry/images",
            accepted_status=[requests.codes.ok],
            json=payload,
        ).json()

    def get_image_tags(self, image: str):
        """Get image tags.

        Parameters
        ----------
        image : str
            image name.

        Returns
        -------
        dict
            MS API response containing image tags.
        """
        payload = {"image": image}
        return self.ms.post(
            "nerve/registry/image-tags",
            accepted_status=[requests.codes.ok],
            json=payload,
        ).json()

    def check_image_status(self, images: list[str] = []):
        """Check image status.

        Parameters
        ----------
        images : list[str]
            image name(s).

        Returns
        -------
        dict
            MS API response containing image status.
        """
        payload = {"images": images}
        return self.ms.post(
            "nerve/registry/check-images-status",
            accepted_status=[requests.codes.ok],
            json=payload,
        ).json()

    def delete_image_tag(self, image: str, tag: str):
        """Delete image tag.

        Parameters
        ----------
        image : str
            image name.
        tag : str
            tag name.
        """
        payload = {"image": image, "tag": tag}
        return self.ms.post(
            "nerve/registry/delete-image-tag",
            accepted_status=[requests.codes.ok],
            json=payload,
        ).json()
