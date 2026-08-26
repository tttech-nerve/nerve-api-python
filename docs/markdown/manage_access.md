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

    `relationship(type='group-user', membership='', target='')`
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

    `ldap_payload(self, url: str, file_name: str = '', name: str = 'ldap_config', port: int = 389, active: bool = False, bind_dn: str = '', password: str = '', tls: bool = False, recurring_sync=None, relationship=None, users=None, groups=None)`
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

    `query_groups(self, password, search_base='', filter='', group_name='', admin_group='', default_role='')`
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

    `query_users(self, password, search_base='', filter='', first_name='', last_name='', email='', username='')`
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

    `save_sync_ldap(self, action: str, file_name: str, ldap_payload: dict)`
    :   Send LDAP configuration payload with populated data from other functions.
        
        Parameters
        ----------
        action : str
            Action to perform on the LDAP configuration. Can be either "sync" or "save".
        file_name : str
            File name of the saved configuration.
        ldap_payload : dict
            LDAP configuration payload.
        
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

    `test_connection(self, url: str, port=389, bind_dn='', password='', secure=False)`
    :   Test LDAP server connection.
        
        Parameters
        ----------
        url : str
            URL of the LDAP server.
        port : int
            Port of the LDAP server. Port 389 is the default port for unencrypted LDAP communication.
        bind_dn : str
            Bind DN of the LDAP server.
        password : str
            Password of the LDAP server.
        secure : bool
            Enable TLS for LDAP communication (switching between unecrypted and encrypted ports).
        
        Returns
        -------
        type
            connected: bool

`LocalUser(node_handle)`
:   User management related functions from MS.
    
    Parameters
    ----------
    node_handle :
        node handle 'nerve_lib.general_utils.NodeHandle(...)'.

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

    `create_access_token(self, name: str, permissions: list[str], expiration_date: str = '') ‑> dict`
    :   Create API access token for authenticated user.
        
        Parameters
        ----------
        name : str
            Display name of the access token.
        permissions : list[str]
            Permissions as names (e.g. 'NODE:VIEW') or permission IDs.
        expiration_date : str, optional
            Expiration date in ISO 8601 format, e.g. '2027-01-01T00:00:00.000Z'.
        
        Returns
        -------
        dict
            Created access token payload. Token secret is returned once.

    `delete(self, email)`
    :   Delete a user from the MS.

    `delete_access_token(self, token_id: str = '', token_name: str = '') ‑> bool`
    :   Delete API access token for authenticated user.
        
        Parameters
        ----------
        token_id : str, optional
            Access token ID.
        token_name : str, optional
            Access token name. Used to resolve token ID if token_id is not provided.
        
        Returns
        -------
        bool
            True if token is deleted successfully.

    `edit(self, email: str, roles: list | None = None, first_name='', last_name='', role_type='local')`
    :   Edit an existing user.

    `get(self, email='', role_type='local')`
    :   Get a list of users.

    `get_access_tokens(self, name: str = '', status: str = '') ‑> dict | list`
    :   Get API access tokens for the authenticated user.
        
        Parameters
        ----------
        name : str, optional
            Token name to select a single access token. Default is "".
        status : str, optional
            Filter tokens by status ('active', 'revoked', 'expired'). Default is "".
        
        Returns
        -------
        dict | list
            Without filters: full response payload from MS.
            With status only: list of filtered access tokens.
            With name: single matching token.

    `get_current_user(self)`
    :

    `get_user_permissions(self, email: str = '', role_type: str = 'local', token_name: str = '') ‑> list[str]`
    :

    `personal_edit(self, email: str, first_name='', last_name='', old_password='', new_password='', confirm_new_password='', user_id='')`
    :   Edit an personal user.

    `revoke_access_token(self, token_id: str = '', token_name: str = '') ‑> dict`
    :   Revoke API access token for authenticated user.
        
        Parameters
        ----------
        token_id : str, optional
            Access token ID.
        token_name : str, optional
            Access token name. Used to resolve token ID if token_id is not provided.

    `unblock_access_token_brute_force(self, ip_address: str = '', token_id: str = '') ‑> None`
    :   Unblock access token brute-force state.
        
        Removes brute-force block state for either an IP address or an access token identifier.
        Exactly one of the two parameters must be provided.
        
        Parameters
        ----------
        ip_address : str, optional
            IPv4 address whose access-token brute-force block state should be removed.
        token_id : str, optional
            Access token identifier whose brute-force block state should be removed.