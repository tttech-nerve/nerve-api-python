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

"""Manage Notifications releated function on MS.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSNotifications
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     notifications = MSNotifications(ms_handle)
    >>>     notifications.get()
    <list of available notifications>
"""

import os

import requests


class MSNotifications:
    """Create opensearch requets.

    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.
    """

    def __init__(self, ms_handle):
        self.ms = ms_handle
        self._log = ms_handle._log.getChild("Notification")

    @staticmethod
    def __prepare_content(text_header, text_msg, image_path, active, show_before_login, image_open=None):
        m_enc_data = {
            "headerText": text_header,
            "textMessage": text_msg,
            "active": str(active).lower(),
            "showBeforeLogin": str(show_before_login).lower(),
        }
        if image_path:
            image_type = os.path.splitext(image_path)[-1][1:]
            if image_type == "jpg":
                image_type = "jpeg"
            m_enc_data["image"] = (
                os.path.basename(image_path),
                image_open,
                f"image/{image_type}",
            )
        return m_enc_data

    def create(self, text_header, text_msg, image_path="", active=True, show_before_login=False):
        """Create a new notification item."""
        with open(image_path, "rb") if image_path else None as image_open:
            m_enc_data = self.__prepare_content(
                text_header, text_msg, image_path, active, show_before_login, image_open
            )
            resp = self.ms.post(
                "/nerve/notifications",
                m_enc_data=m_enc_data,
                accepted_status=[requests.codes.ok],
            )
        self._log.info("Created Notification %s", text_header)
        return resp.json()

    def edit(
        self,
        notification_id,
        text_header,
        text_msg,
        image_path="",
        active=True,
        show_before_login=False,
    ):
        """Edit an existing notification item."""
        with open(image_path, "rb") if image_path else None as image_open:
            m_enc_data = self.__prepare_content(
                text_header, text_msg, image_path, active, show_before_login, image_open
            )
            resp = self.ms.put(
                f"/nerve/notifications/{notification_id}",
                m_enc_data=m_enc_data,
                accepted_status=[requests.codes.ok],
            )

        self._log.info("Edited Notification %s", text_header)
        return resp.json()

    def get(self):
        """Read list of all notification items."""
        return self.ms.get("/nerve/notifications", accepted_status=[requests.codes.ok]).json()["data"]

    def get_details(self, read_item: str) -> dict:
        """Read notification details regarding one element.

        Parameters
        ----------
        read_item : str
            can be a specific notification._id or 'active' or 'activeNoAuth'.

        Returns
        -------
        dict
            matching notification item.
        """
        return self.ms.get(f"/nerve/notifications/{read_item}", accepted_status=[requests.codes.ok]).json()

    def delete(self, notification_id=None):
        """Delete a notification item(s)."""
        if notification_id:
            # Delete a specific notification item.
            self.ms.delete(f"/nerve/notifications/{notification_id}")
            self._log.info("Removed notification with id %s", notification_id)
        else:
            # Delete all notification items.
            notifications = self.get()
            while notifications:
                for notification in notifications:
                    self.delete(notification["_id"])
                notifications = self.get()
            self._log.info("All notifications have been removed.")

    def configure_usage_reports(self, notify_tttech: bool) -> dict:
        """Configure usage reports.

        Automatically transport monthly report to nerve-billing@tttech-industrial.com.

        Parameters
        ----------
        notify_tttech : bool
            Whether to notify TTTech.

        Returns
        -------
        dict
            API response: {updated: true}
        """
        return self.ms.post(
            "/nerve/usage-reports/configuration",
            json={"notifyTTTech": notify_tttech},
            accepted_status=[requests.codes.ok],
        ).json()

    def download_monthly_report(self, month: str, year: int):
        """Download the monthly usage report.

        Parameters
        ----------
        month : str
            The month for the report (e.g., "April").
        year : int
            The year for the report.

        Returns
        -------
            Response object for the download request.
        """
        return self.ms.get(
            "/nerve/usage-reports/single",
            params={"month": month, "year": year},
            accepted_status=[requests.codes.ok],
        ).json()
