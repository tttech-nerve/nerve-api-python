[back (nerve_lib)](./index.md)

Module nerve_lib.manage_access
==============================
Manage Access releated function on MS.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSUser
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     user = MSUser(ms_handle)
    >>>     user.get()
    <current user-list>

Classes
-------

`InternalTestAPI(ms_handle)`
:   Manage Internal Test API related functions. NOT FOR PRODUCTION USE!

    ### Methods

    `get_value(self, parameter: str)`
    :   Get a specific configuration value.
        
        Parameters
        ----------
        parameter : str
            Name of the top-level key in the configuration.yaml file.
        
        Returns
        -------
        type
            Configuration value for the specified parameter.

    `reset_value(self, parameter: str, configuration: str)`
    :   Reset a specific configuration value to its default.
        
        Parameters
        ----------
        parameter : str
            Name of the top-level key in the configuration.yaml file.
        
        Returns
        -------
        type
            Response from the reset request.

    `set_value(self, parameter: str, configuration: <module 'json' from '/home/schierl/.pyenv/versions/3.14.2/lib/python3.14/json/__init__.py'>)`
    :   Set a specific configuration value.
        
        Parameters
        ----------
        parameter : str
            Name of the top-level key in the configuration.yaml file.
        
        Returns
        -------
        type
            Response from the set request.

`LDAP(ms_handle)`
:   LDAP management related functions from MS.
    
    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.

    ### Static methods

    `groups(search_base='', filter='', group_name='', admin_group='', default_role='')`
    :   Set groups details.
        
        Parameters
        ----------
        search_base : str
            Search base for LDAP configuration.
        filter : str
            Groups filter for LDAP configuration.
        group_name : str
            Group name for LDAP configuration.
        admin_group : str
            Admin group for LDAP configuration.
        default_role: str
            Default role for LDAP configuration.
        
        Returns
        -------
        type
            groups payload

    `recurring_sync(recurring_sync=False, schedule='', time='')`
    :   Set recurring sync details.
        
        Parameters
        ----------
        recurring_sync : bool
            Status of recurring sync for LDAP configuration.
        schedule : str
            Schedule type for recurring sync.
        time : str
            Time for recurring sync.
        
        Returns
        -------
        type
            recurringSync payload

    `relationship(type='', membership='', target='')`
    :   Set relationship details.
        
        Parameters
        ----------
        type: str
            Relationship type for LDAP configuration.
        membership : str
            Membership type (Member) for LDAP configuration.
        target: str
            Target type (Target) for LDAP configuration.
        
        Returns
        -------
        type
            relationship payload

    `users(search_base='', filter='', first_name='', last_name='', email='', username='')`
    :   Set users details.
        
        Parameters
        ----------
        search_base : str
            Search base for LDAP configuration.
        filter : str
            Users filter for LDAP configuration.
        first_name : str
            First name for LDAP configuration.
        last_name : str
            Last name for LDAP configuration.
        email: str
            Users email for LDAP configuration.
        username: str
            Users username for LDAP configuration.
        
        Returns
        -------
        type
            users payload

    ### Methods

    `check_active(self)`
    :   Check if LDAP is active.

    `enable_disable_ldap(self, enable: bool)`
    :   Activate LDAP configuration.

    `get_config(self)`
    :   Get LDAP configuration details.

    `get_default(self)`
    :   Get default LDAP configuration.

    `ldap_payload(self, file_name: str = '', name: str = 'ldap_config', url: str = 'ldap.dev.nerve.cloud', port: int = 389, active: bool = False, bind_dn: str = 'cn=admin,dc=tttech,dc=com', password: str = 'Passw0rd', tls: bool = False, recurring_sync=None, relationship=None, users=None, groups=None)`
    :   Set LDAP configuration payload.
        
        Parameters
        ----------
        file_name : str
            File name of the saved configuration.
        name : int
            LDAP configuration name on MS.
        url : str
            URL of the LDAP server.
        port : int
            Port of the LDAP server. Port 389 is the default port for unencrypted LDAP communication.
        active : bool
            Status of the LDAP configuration.
        bind_dn : str
            Bind DN of the LDAP server.
        password : str
            Password of the LDAP server.
        tls : bool
            Enable TLS for LDAP communication (switching between unecrypted and encrypted ports).
        
        Returns
        -------
        type
            LDAP payload

    `query_groups(self, search_base='', filter='', group_name='', admin_group='', default_role='')`
    :   Query groups from LDAP configuration.
        
        Parameters
        ----------
        search_base : str
            Search base for LDAP configuration.
        filter : str
            Groups filter for LDAP configuration.
        group_name : str
            Group name for LDAP configuration.
        admin_group : str
            Admin group for LDAP configuration.
        default_role: str
            Default role for LDAP configuration.
        
        Returns
        -------
        type
            groups query response

    `query_users(self, search_base='', filter='', first_name='', last_name='', email='', username='')`
    :   Query users from LDAP configuration.
        
        Parameters
        ----------
        search_base : str
            Search base for LDAP configuration.
        filter : str
            Users filter for LDAP configuration.
        first_name : str
            First name for LDAP configuration.
        last_name : str
            Last name for LDAP configuration.
        email: str
            Users email for LDAP configuration.
        username: str
            Users username for LDAP configuration.
        
        Returns
        -------
        type
            users query response

    `save_sync_ldap(self, action: str, file_name: str, ldap_payload: dict | None = None, recurring_sync=None, relationship=None, users=None, groups=None)`
    :   Send LDAP configuration payload with populated data from other functions.
        
        Parameters
        ----------
        action : str
            Action to perform on the LDAP configuration. Can be either "sync" or "save".
        file_name : str
            File name of the saved configuration.
        name : str
            LDAP configuration name on MS.
        url : str
            URL of the LDAP server.
        port : int
            Port of the LDAP server.
        active : bool
            Status of the LDAP configuration.
        bind_dn : str
            Bind DN of the LDAP server.
        password : str
            Password of the LDAP server.
        tls : bool
            Enable TLS for LDAP communication.
        
        Returns
        -------
        dict
            Response from the request.

    `set_ldap_state(self, state: bool, name: str)`
    :   Set LDAP state.
        
        Parameters
        ----------
        state : bool
            State of LDAP configuration.
        name : str
            Name of the LDAP configuration.
        
        Returns
        -------
        type
            response from the MS

    `test_connection(self, url: str, port=389, bind_dn='cn=admin,dc=tttech,dc=com', password='Passw0rd', secure=False)`
    :   Test LDAP server connection.
        
        Parameters
        ----------
        url : str
            URL of the LDAP server.
        port : int
            Port of the LDAP server. Port 389 is the default port for unencrypted LDAP communication.
        
        Returns
        -------
        type
            connected: bool

`LocalUser(node_handle)`
:   User management related functions from MS.
    
    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.

    ### Methods

    `delete(self, username: str = '')`
    :   Delete all users or a specific user from the node.
        
        Parameters
        ----------
        user : str, optional
            username to delete. The default is None which will delete all users.
        
        Returns
        -------
        type
            response from the node.

    `get(self, username: str = '')`
    :   Get all users or a specific user from the node.

    `user_exists(self, username: str) ‑> bool`
    :   Check if a specific user exists.
        
        Parameters
        ----------
        username : str
            username to check.
        
        Returns
        -------
        bool
            True if the user exists, False otherwise.

`MSRole(ms_handle)`
:   Role management related functions from MS.
    
    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.

    ### Methods

    `add(self, name: str, permission_names: list, description: str = '')`
    :   Add a new role to the MS.

    `delete(self, name: str)`
    :   Delete a role from MS.

    `edit(self, role_name: str, new_role_name: str, permission_names: list, description: str = ' ', type: str = 'local', config_name: str = 'ldap_config')`
    :   Update an existing role.

    `get(self, name: str = '', role_type: str = 'local')`
    :   Get list of available roles in MS.

    `get_permission_api(self, name_filter: str = '')`
    :   Get list of permissions for all classes (API).

    `get_permission_ui(self, name_filter: str = '')`
    :   Get list of permissions for UI class.

`MSUser(ms_handle)`
:   User management related functions from MS.
    
    Parameters
    ----------
    node_handle :
        handle to node 'nerve_lib.general_utils.NodeHandle(...)'.

    ### Methods

    `add(self, email: str, roles: list, first_name: str = '', last_name: str = '', role_type: str = 'local') ‑> dict`
    :   Add a new user to the MS.

    `delete(self, email)`
    :   Delete a user from the MS.

    `edit(self, email: str, roles: list = [], first_name='', last_name='', role_type='local')`
    :   Edit an existing user.

    `extract_endpoints(self, openapi_spec, output_json)`
    :   Extract endpoints from OpenAPI specification and save to JSON file.

    `get(self, email='', role_type='local')`
    :   Get a list of users.

    `personal_edit(self, email: str, first_name='', last_name='', old_password='', new_password='', confirm_new_password='', user_id='')`
    :   Edit an personal user.