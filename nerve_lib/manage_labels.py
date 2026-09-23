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
import yaml

"""Manage Labels on Node, MS and workloads.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSLabel
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     labels = MSLabel(ms_handle)
    >>>     labels.get_label("key", "value")
    <dict label item of MS>
"""

import requests


class MSLabel:
    """Label creation and manipulation functions.

    Parameters
    ----------
    ms_handle : type
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.
    """

    def __init__(self, ms_handle: type):
        self.ms = ms_handle
        self._log = ms_handle._log.getChild("MSLabel")

    def fetch_labels(self) -> dict:
        """Fetch labels from labels list.

        Parameters
        ----------
        page_number : int, optional
            Page of results to be returned. The default is 0.
        limit : int, optional
            Number of labels to be returned. The default is 100.

        Returns
        -------
        dict
            label list, response from api object.
        """
        labels = {"count": 0, "data": []}
        page_number = 1
        while True:
            labels_single_read = self.ms.get(
                "/nerve/labels/list",
                params={"limit": 50, "page": page_number},
                accepted_status=[requests.codes.ok],
            ).json()
            page_number += 1
            labels["data"] += labels_single_read.get("data", [])
            labels["count"] = labels_single_read["count"]
            if len(labels["data"]) == labels_single_read["count"]:
                break
        return labels

    def get_label(self, key: str, value: str) -> dict:
        """Read specific label from MS.

        Parameters
        ----------
        key : str
            label key.
        value : str
            label value.

        Returns
        -------
        dict
            if key/value exists, dict containing _id, key, value is returned.
        """
        labels = self.fetch_labels()
        for label in labels.get("data", []):
            if key == label.get("key") and value == label.get("value"):
                return {"_id": label.get("_id"), "key": label.get("key"), "value": label.get("value")}
        msg = f"Label {key}:{value} does not exist"
        raise ValueError(msg)

    def create_label(self, key: str, value: str) -> dict:
        """Create a single label.

        Parameters
        ----------
        key : str
            Label name/key.
        value : str
            Label value.

        Returns
        -------
        dict
            label creation response as dict.
        """
        response = self.ms.post(
            url="/nerve/labels",
            json={"key": key, "value": value},
            accepted_status=[requests.codes.ok, requests.codes.conflict],
        )
        self._log.info(
            "Label %s:%s created"
            if response.status_code == requests.codes.ok
            else "Label %s:%s already created",
            key,
            value,
        )
        return response.json()

    def set_dut_labels(self, node: type, label_list: list):
        """Add an existing label to a Node.

        Parameters
        ----------
        node : type
            handle to NodeHandle class.
        label_list : list
            list containing [(key, value), (key1, value2), ...]
        """
        node_list = self.ms.get("/nerve/nodes/list", accepted_status=[requests.codes.ok]).json()
        node_list_info = next(filter(lambda x: x.get("serialNumber") == node.serial_number, node_list))
        node_detailed_info = self.ms.get(
            f"/nerve/node/{node_list_info.get('_id')}",
            accepted_status=[requests.codes.ok],
        ).json()
        labels = []
        for key, value in label_list:
            labels.append(self.get_label(key, value))
        payload = {
            "nodeId": node_list_info.get("_id"),
            "labels": labels,
            "model": node_detailed_info.get("model"),
            "name": node_list_info.get("name"),
            "remoteConnections": [],
            "serialNumber": node.serial_number,
            "deleted": False,
        }
        if self.ms.version_smaller_than("2.10.0"):
            payload["secureId"] = node_list_info.get("secureId")
        self.ms.patch("/nerve/node", json=payload)
        self._log.info(
            "Labels %s set on node %s",
            [f"{label['key']}:{label['value']}" for label in labels],
            node_list_info.get("name"),
        )

    def add_dut_label(self, node, key: str, value: str):
        """Add a label to a node.

        Parameters
        ----------
        node : TYPE
            node handle.
        key : str
            key of the label.
        value : str
            value of the label.
        """
        node_list = self.ms.get("/nerve/nodes/list", accepted_status=[requests.codes.ok]).json()
        node_list_info = next(filter(lambda x: x.get("serialNumber") == node.serial_number, node_list))
        node_detailed_info = self.ms.get(
            f"/nerve/node/{node_list_info.get('_id')}",
            accepted_status=[requests.codes.ok],
        ).json()
        labels = node_detailed_info.get("labels", [])
        label_list = [(label["key"], label["value"]) for label in labels]
        label_list.append((key, value))
        self.set_dut_labels(node, label_list)

    def update(self, label_key: str, new_label_key: str, label_value: str, new_label_value: str):
        """Update an existing label."""
        existing_label = self.get_label(label_key, label_value)

        if new_label_key:
            existing_label["key"] = new_label_key
        if new_label_value:
            existing_label["value"] = new_label_value

        self.ms.patch(
            f"/nerve/labels/{existing_label['_id']}",
            json=existing_label,
            accepted_status=[requests.codes.ok],
        )

    def delete(self, label_key, label_value):
        """Delete a label from the MS."""
        try:
            response = self.get_label(label_key, label_value)
            label_id = response["_id"]

            self._log.info("Deleting Label %s:%s", response["key"], response["value"])
            self.ms.delete(f"/nerve/labels/{label_id}", accepted_status=[requests.codes.ok])
        except ValueError as ex_msg:
            self._log.warning("Label with %s:%s does not exist: %s", label_key, label_value, ex_msg)

    def merge(self, keys: list, new_key_name: str):
        """
        Merge existing labels into a new key.

        Args:
            keys (list): List of existing label keys to be merged.
            newKeyName (str): New key name to merge the labels into.

        Returns
        -------
            dict: Merged label information.
        """
        payload = {
            "keys": keys,
            "newKeyName": new_key_name,
        }
        return self.ms.patch(
            "/nerve/labels/merge",
            json=payload,
            accepted_status=[requests.codes.ok],
        ).json()

    def delete_all(self):
        """Delete all labels from the MS."""
        labels = self.fetch_labels()
        for label in labels.get("data", []):
            self.delete(label.get("key"), label.get("value"))
        self._log.info("All labels deleted")
        return True

    @classmethod
    def get_node_labels(cls, node):
        """Get all labels from a node.

        Parameters
        ----------
        node : TYPE
            node handle.

        Returns
        -------
        list
            list of labels on the node.
        """
        node_info = node.get_details()
        return node_info.get("labels", [])

    def add_node_label(self, node, key: str, value: str, suppress_log: bool = False):
        """Add a label to a node.

        Parameters
        ----------
        node : TYPE
            node handle.
        key : str
            key of the label.
        value : str
            value of the label.
        """
        node_info = node.get_details()
        label_id = None
        try:
            label_id = self.get_label(key, value)["_id"]
        except ValueError:
            pass
        labels_add = {"key": key, "value": value}
        if label_id:
            labels_add = {"_id": label_id, "key": key, "value": value}
            if next((label for label in node_info.get("labels", []) if label["_id"] == label_id), None):
                self._log.info(
                    "Label '%s=%s' already exists on node %s", key, value, node_info["serialNumber"]
                )
                return
        self.ms.patch(
            f"/nerve/node/{node_info['serialNumber']}/labels/assign",
            json={"labels": [labels_add]},
            accepted_status=[requests.codes.ok],
        )
        if not suppress_log:
            self._log.info("Label '%s=%s' added to node %s", key, value, node_info["serialNumber"])

    def del_node_label(self, node, key: str, suppress_log: bool = False):
        """Delete a label from a node.

        Parameters
        ----------
        node : TYPE
            node handle.
        key : str
            key of the label.
        """
        node_info = node.get_details()
        label_id = next((label["_id"] for label in node_info.get("labels", []) if label["key"] == key), None)
        if label_id:
            self.ms.patch(
                f"/nerve/node/{node_info['serialNumber']}/labels/unassign",
                json={"labels": [label_id]},
                accepted_status=[requests.codes.ok],
            )
            if not suppress_log:
                self._log.info("Label '%s' deleted from node %s", key, node_info["serialNumber"])
        else:
            raise ValueError(f"Label '{key}' does not exist on node {node_info['serialNumber']}")

    def edit_node_label(self, node, key: str, value: str):
        """Edit a label on a node.

        Parameters
        ----------
        node : TYPE
            node handle.
        key : str
            key of the label.
        value : str
            value of the label.
        """
        self.del_node_label(node, key, suppress_log=True)
        self.add_node_label(node, key, value, suppress_log=True)
        self._log.info("Label '%s' edited to '%s' on node %s", key, value, node.get_details()["serialNumber"])

    def export_node_labels(self, node) -> dict:
        """Export all labels from a node.

        Parameters
        ----------
        node : TYPE
            node handle.

        Returns
        -------
        dict
            Exported labels as a dictionary.
        """
        node_info = node.get_details()
        response = self.ms.get(
            f"/nerve/node/{node_info['serialNumber']}/labels/export", accepted_status=[requests.codes.ok]
        )
        self._log.info("Labels exported from node %s", node_info["serialNumber"])
        return yaml.safe_load(response.content.decode("utf-8"))

    def import_node_labels(self, node, labels: dict):
        """Import labels to a node.

        Parameters
        ----------
        node : TYPE
            node handle.
        labels : dict
            Labels as a dictionary to be imported.
        """
        node_info = node.get_details()

        m_enc_data = {"data": ("file.yaml", yaml.dump(labels), "application/x-yaml")}
        self.ms.patch(
            f"/nerve/node/{node_info['serialNumber']}/labels/import",
            m_enc_data=m_enc_data,
            accepted_status=[requests.codes.ok],
        )
        self._log.info("Labels imported to node %s", node_info["serialNumber"])
