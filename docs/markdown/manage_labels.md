[back (nerve_lib)](./index.md)

Module nerve_lib.manage_labels
==============================

Classes
-------

`MSLabel(ms_handle: type)`
:   Label creation and manipulation functions.
    
    Parameters
    ----------
    ms_handle : type
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.

    ### Static methods

    `get_node_labels(node)`
    :   Get all labels from a node.
        
        Parameters
        ----------
        node : TYPE
            node handle.
        
        Returns
        -------
        list
            list of labels on the node.

    ### Methods

    `add_dut_label(self, node, key: str, value: str)`
    :   Add a label to a node.
        
        Parameters
        ----------
        node : TYPE
            node handle.
        key : str
            key of the label.
        value : str
            value of the label.

    `add_node_label(self, node, key: str, value: str, suppress_log: bool = False)`
    :   Add a label to a node.
        
        Parameters
        ----------
        node : TYPE
            node handle.
        key : str
            key of the label.
        value : str
            value of the label.

    `create_label(self, key: str, value: str) ‑> dict`
    :   Create a single label.
        
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

    `del_node_label(self, node, key: str, suppress_log: bool = False)`
    :   Delete a label from a node.
        
        Parameters
        ----------
        node : TYPE
            node handle.
        key : str
            key of the label.

    `delete(self, label_key, label_value)`
    :   Delete a label from the MS.

    `delete_all(self)`
    :   Delete all labels from the MS.

    `edit_node_label(self, node, key: str, value: str)`
    :   Edit a label on a node.
        
        Parameters
        ----------
        node : TYPE
            node handle.
        key : str
            key of the label.
        value : str
            value of the label.

    `export_node_labels(self, node) ‑> dict`
    :   Export all labels from a node.
        
        Parameters
        ----------
        node : TYPE
            node handle.
        
        Returns
        -------
        dict
            Exported labels as a dictionary.

    `fetch_labels(self) ‑> dict`
    :   Fetch labels from labels list.
        
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

    `get_label(self, key: str, value: str) ‑> dict`
    :   Read specific label from MS.
        
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

    `import_node_labels(self, node, labels: dict)`
    :   Import labels to a node.
        
        Parameters
        ----------
        node : TYPE
            node handle.
        labels : dict
            Labels as a dictionary to be imported.

    `merge(self, keys: list, new_key_name: str)`
    :   Merge existing labels into a new key.
        
        Args:
            keys (list): List of existing label keys to be merged.
            newKeyName (str): New key name to merge the labels into.
        
        Returns
        -------
            dict: Merged label information.

    `set_dut_labels(self, node: type, label_list: list)`
    :   Add an existing label to a Node.
        
        Parameters
        ----------
        node : type
            handle to NodeHandle class.
        label_list : list
            list containing [(key, value), (key1, value2), ...]

    `update(self, label_key: str, new_label_key: str, label_value: str, new_label_value: str)`
    :   Update an existing label.