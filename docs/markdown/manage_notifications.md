[back (nerve_lib)](./index.md)

Module nerve_lib.manage_notifications
=====================================
Manage Notifications releated function on MS.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSNotifications
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     notifications = MSNotifications(ms_handle)
    >>>     notifications.get()
    <list of available notifications>

Classes
-------

`MSNotifications(ms_handle)`
:   Create opensearch requets.
    
    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.

    ### Methods

    `configure_usage_reports(self, notify_tttech: bool) ‑> dict`
    :   Configure usage reports.
        
        Automatically transport monthly report to nerve-billing@tttech-industrial.com.
        
        Parameters
        ----------
        notify_tttech : bool
            Whether to notify TTTech.
        
        Returns
        -------
        dict
            API response: {updated: true}

    `create(self, text_header, text_msg, image_path='', active=True, show_before_login=False)`
    :   Create a new notification item.

    `delete(self, notification_id=None)`
    :   Delete a notification item(s).

    `download_monthly_report(self, month: str, year: int)`
    :   Download the monthly usage report.
        
        Parameters
        ----------
        month : str
            The month for the report (e.g., "April").
        year : int
            The year for the report.
        
        Returns
        -------
            Response object for the download request.

    `edit(self, notification_id, text_header, text_msg, image_path='', active=True, show_before_login=False)`
    :   Create a new notification item.

    `get(self)`
    :   Read list of all notification items.

    `get_details(self, read_item: str) ‑> dict`
    :   Read notification details regarding one element.
        
        Parameters
        ----------
        read_item : str
            can be a specific notification._id or 'active' or 'activeNoAuth'.
        
        Returns
        -------
        dict
            matching notification item.