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

"""Manage Access releated function on MS.

Example:
-------
    >>> from nerve_lib import MSHandle
    >>> from nerve_lib import MSUser
    >>> with MSHandle("testms.nerve.cloud") as ms_handle:
    >>>     user = MSUser(ms_handle)
    >>>     user.get()
    <current user-list>
"""

import json
import re

import requests


class MSRole:
    """Role management related functions from MS.

    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.
    """

    def __init__(self, ms_handle):
        self.ms = ms_handle
        self._log = ms_handle._log.getChild("Role")

    def get(self, name: str = "", role_type: str = "local"):
        """Get list of available roles in MS."""
        role_list = self.ms.get(
            "/nerve/rbac/roles",
            params=[{"filterBy[type]", role_type}],
            accepted_status=[requests.codes.ok],
        ).json()
        if not name:
            return role_list
        try:
            return next(role for role in role_list if role["name"] == name)
        except StopIteration:
            msg = f"Role '{name}' not in role_type '{role_type}' ({[role['name'] for role in role_list]})"
            raise ValueError(msg)

    def get_permission_ui(self, name_filter: str = ""):
        """Get list of permissions for UI class."""
        return self.ms.get(
            "/nerve/rbac/permissions",
            params={"categories": "UI_PERMISSION", "filterBy": f'{{"name":"{name_filter}"}}'},
            accepted_status=[requests.codes.ok],
        ).json()

    def get_permission_api(self, name_filter: str = ""):
        """Get list of permissions for all classes (API)."""
        all_permissions = self.ms.get(
            "/nerve/rbac/permissions",
            params={"categories": [], "filterBy": f'{{"name":"{name_filter}"}}'},
            accepted_status=[requests.codes.ok],
        ).json()
        ui_permissions = self.get_permission_ui(name_filter)
        # remove ui_permissions from all_permissions
        return {
            "data": [
                perm
                for perm in all_permissions["data"]
                if perm["_id"] not in {p["_id"] for p in ui_permissions["data"]}
            ],
        }

    def add(self, name: str, permission_names: list, description: str = ""):
        """Add a new role to the MS."""
        available_permissions = self.get_permission_api()
        permission_ids = []
        for perm_name in permission_names:
            try:
                permission_ids.append(
                    next(perm["_id"] for perm in available_permissions["data"] if perm["name"] == perm_name),
                )
            except StopIteration:
                msg = (
                    f"Permission '{perm_name}' not valid, use one of "
                    f"({[perm['name'] for perm in available_permissions['data']]}"
                )
                raise ValueError(msg)
        payload = {
            "id": "",
            "name": name,
            "description": description or name,
            "defaultRole": False,
            "permissions": permission_ids,
            "users": [],
            "_prettyRoleName": "Data",
            "type": "local",
            "ldap": {},
        }
        response = self.ms.post(
            "/nerve/rbac/roles",
            json=payload,
            accepted_status=[requests.codes.ok, requests.codes.conflict],
        )
        if response.status_code == requests.codes.conflict:
            self._log.warning("Role already exists, role is not updated")

    def delete(self, name: str):
        """Delete a role from MS."""
        role_id = self.get(name)["_id"]
        self.ms.delete(f"/nerve/rbac/roles/{role_id}")

    def edit(
        self,
        role_name: str,
        new_role_name: str,
        permission_names: list,
        description: str = " ",
        type: str = "local",
        config_name: str = "ldap_config",
    ):
        """Update an existing role."""
        if type == "ldap":
            existing_role = self.get(f"{role_name} - {config_name}", type)
        else:
            existing_role = self.get(role_name)

        # Get available permissions
        available_permissions = self.get_permission_api()

        # Convert permission names to IDs
        permission_ids = []
        for perm_name in permission_names:
            try:
                perm_id = next(
                    perm["_id"] for perm in available_permissions["data"] if perm["name"] == perm_name
                )
                permission_ids.append(perm_id)
            except StopIteration:
                msg = (
                    f"Permission '{perm_name}' not valid, use one of "
                    f"({[perm['name'] for perm in available_permissions['data']]}"
                )
                raise ValueError(msg)

        # Update fields only if they are provided
        role_id = existing_role["_id"]
        if type == "ldap":
            existing_role["id"] = ""
            existing_role["_prettyRoleName"] = role_name
            existing_role.pop("_id", None)
            existing_role.pop("__v", None)

        if new_role_name:
            existing_role["name"] = new_role_name
        if description:
            existing_role["description"] = description
        existing_role["permissions"] = permission_ids

        # Make the PATCH request to update the role
        self.ms.patch(
            f"/nerve/rbac/roles/{role_id}",
            json=existing_role,
            accepted_status=[requests.codes.ok],
        )


class MSUser:
    """User management related functions from MS.

    Parameters
    ----------
    node_handle :
        handle to node 'nerve_lib.general_utils.NodeHandle(...)'.
    """

    def __init__(self, ms_handle):
        self.ms = ms_handle
        self._log = ms_handle._log.getChild("User")
        self._role = MSRole(ms_handle)

    def get(self, email="", role_type="local"):
        """Get a list of users."""
        user_list = self.ms.get(
            "/crm/profile/list" if self.ms.version_smaller_than("3.2.0") else "/crm/profiles",
            params={"limit": 500, "filterBy[type]": role_type},
            accepted_status=[requests.codes.ok],
        ).json()
        if email:
            try:
                return next(
                    user
                    for user in user_list["data" if self.ms.version_smaller_than("3.2.0") else "profiles"]
                    if user["username"] == email
                )
            except StopIteration:
                msg = (
                    f"User '{email}' not in role_type '{role_type}' "
                    f"({[user['username'] for user in user_list['data' if self.ms.version_smaller_than('3.2.0') else 'profiles']]})"
                )
                raise ValueError(msg)
        return user_list

    def add(
        self, email: str, roles: list, first_name: str = "", last_name: str = "", role_type: str = "local"
    ) -> dict:
        """Add a new user to the MS."""
        if not re.match(r"^[_a-z0-9-]+(.[_a-z0-9-]+)*@[a-z0-9-]+(.[a-z0-9-]+)*(.[a-z]{2,4})$", email):
            self._log.error("Invalid email specified: %s", email)
            msg = f"Error: Invalid email specified: {email}"
            raise RuntimeError(msg)
        uname = [name.capitalize() for name in email.split("@", maxsplit=1)[0].split(".", 1)]

        role_ids = [self._role.get(role, role_type)["_id"] for role in roles]

        payload = {
            "firstName": first_name or uname[0],
            "lastName": last_name or uname[-1],
            "username": email,
            "profileImgURL": "",
            "mfaEnabled": False,
            "roles": role_ids,
        }

        m_enc_data = {"data": (None, json.dumps(payload), "form-data")}

        response = self.ms.post(
            "/crm/profile",
            m_enc_data=m_enc_data,
            accepted_status=[requests.codes.ok, requests.codes.created],
        )
        return response.json()

    def edit(self, email: str, roles: list | None = None, first_name="", last_name="", role_type="local"):
        """Edit an existing user."""
        payload = self.get(email, role_type)

        if roles:
            role_ids = [self._role.get(role, role_type)["_id"] for role in roles]
            payload["roles"] = role_ids
        else:
            role_dicts = payload.get("roles", [])
            payload["roles"] = [role_dict["_id"] for role_dict in role_dicts]

        if first_name:
            payload["firstName"] = first_name

        if last_name:
            payload["lastName"] = last_name

        payload["profileImgURL"] = ""
        payload["id"] = payload.pop("_id")
        payload["mfaEnabled"] = False

        payload.pop("auth", None)
        payload.pop("created", None)
        payload.pop("preferences", None)
        payload.pop("type", None)

        m_enc_data = {"data": (None, json.dumps(payload), "form-data")}

        response = self.ms.put(
            f"/crm/profile/{payload.get('id')}",
            m_enc_data=m_enc_data,
            accepted_status=[requests.codes.ok],
        )
        return response.json()

    def delete(self, email):
        """Delete a user from the MS."""
        user_id = self.get(email)["_id"]
        self.ms.delete(f"/crm/profile/{user_id}")

    def personal_edit(
        self,
        email: str,
        first_name="",
        last_name="",
        old_password="",
        new_password="",
        confirm_new_password="",  # nosec B107
        user_id="",
    ):
        """Edit an personal user."""
        if not user_id:
            user_id = self.get(email)["_id"]
        payload = {
            "id": user_id,
            "firstName": first_name or self.get(email)["firstName"],
            "lastName": last_name or self.get(email)["lastName"],
            "username": email,
            "email": email,
            "mfaEnabled": False,
            "profileImgURL": "",
            "currentPassword": old_password,
            "newPassword": new_password,
            "confirmPassword": confirm_new_password,
        }
        if self.ms.version_smaller_than("3.2.0"):
            payload["preferredLanguage"] = "en_EN"
        if not old_password and not new_password and not confirm_new_password:
            payload.pop("currentPassword")
            payload.pop("newPassword")
            payload.pop("confirmPassword")

        m_enc_data = {"data": (None, json.dumps(payload), "form-data")}

        response = self.ms.put(
            "/crm/personalProfile" if self.ms.version_smaller_than("3.2.0") else "/crm/personal-profile",
            m_enc_data=m_enc_data,
            accepted_status=[requests.codes.ok],
        )
        return response.json()

    def get_current_user(self):
        if self.ms.access_token:
            raise RuntimeError("get_current_user() is not supported with token-based authentication")

        users = self.get()
        user_id = next(
            (
                user["_id"]
                for user in users["data" if self.ms.version_smaller_than("3.2.0") else "profiles"]
                if user["username"] == self.ms.usr
            ),
            None,
        )
        if not user_id:
            raise ValueError(f"Current user '{self.ms.usr}' not found in MS")
        return self.ms.get(f"/crm/profile/{user_id}", accepted_status=[requests.codes.ok]).json()

    def get_user_permissions(
        self, email: str = "", role_type: str = "local", token_name: str = ""
    ) -> list[str]:
        if token_name:
            token_info = self.get_access_tokens(name=token_name)
            if not token_info:
                raise ValueError(f"Access token '{token_name}' not found")
            user_id = token_info.get("userId")
            user_info = self.ms.get(f"/crm/profile/{user_id}", accepted_status=[requests.codes.ok]).json()
        elif email:
            user_info = self.get(email=email, role_type=role_type)
        else:
            user_info = self.get_current_user()

        role_permissions = self._role.get_permission_api()
        permissions = []
        for role in user_info.get("roles", []):
            role_info = self._role.get(name=role["name"], role_type=role["type"])
            role_permission_names = [
                perm["name"]
                for perm in role_permissions["data"]
                if perm["_id"] in role_info.get("permissions", [])
            ]
            permissions.extend(role_permission_names)

        self._log.debug("User '%s' has the following permissions: %s", user_info["username"], permissions)
        return permissions

    def get_access_tokens(self, name: str = "", status: str = "") -> dict | list:
        """Get API access tokens for the authenticated user.

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
        """
        access_token_response = self.ms.get(
            "/crm/v1/access-tokens",
            accepted_status=[requests.codes.ok],
        ).json()

        access_tokens = access_token_response.get("accessTokens", [])

        if status:
            access_tokens = [token for token in access_tokens if token.get("status") == status]

        if not name:
            return access_tokens if status else access_token_response

        try:
            return next(token for token in access_tokens if token.get("name") == name)
        except StopIteration:
            msg = f"Access token '{name}' not found ({[token.get('name') for token in access_tokens]})"
            raise ValueError(msg)

    def get_access_token_creation_permissions(self, name_only: bool = True) -> list[str]:
        """Get the possible permissions to create an access_token."""
        user_id = self.get_current_user().get("_id")

        permissions = self.ms.get(
            f"/nerve/rbac/users/{user_id}/permissions/detailed",
            params={"type": "API", "usage": "access_token_creation"},
        ).json()["permissions"]
        if name_only:
            return [perm["name"] for perm in permissions]
        return permissions

    def create_access_token(self, name: str, permissions: list[str], expiration_date: str = "") -> dict:
        """Create API access token for authenticated user.

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
        """
        if not permissions:
            msg = "At least one permission must be provided"
            raise ValueError(msg)
        # Resolve permission names to IDs using the user's available permissions.
        permissions = self.get_access_token_creation_permissions(name_only=False)
        permission_map = {perm["name"]: perm["_id"] for perm in permissions}
        resolved_permission_ids = []
        invalid_permission_names = []
        for permission in permissions:
            permission_name = permission if isinstance(permission, str) else permission.get("name")
            if permission_name in permission_map:
                resolved_permission_ids.append(permission_map[permission_name])
            else:
                invalid_permission_names.append(permission_name)

        if invalid_permission_names:
            msg = f"Permissions {invalid_permission_names} not valid, use one of {[perm['name'] for perm in permissions]}"
            raise ValueError(msg)

        payload = {
            "name": name,
            "permissions": resolved_permission_ids,
        }
        if expiration_date:
            payload["expirationDate"] = expiration_date

        return self.ms.post(
            "/crm/v1/access-tokens",
            json=payload,
            accepted_status=[requests.codes.created],
        ).json()

    def revoke_access_token(self, token_id: str = "", token_name: str = "") -> dict:
        """Revoke API access token for authenticated user.

        Parameters
        ----------
        token_id : str, optional
            Access token ID.
        token_name : str, optional
            Access token name. Used to resolve token ID if token_id is not provided.
        """
        if not token_id and not token_name:
            msg = "token_id or token_name must be provided"
            raise ValueError(msg)

        if not token_id:
            token_id = self.get_access_tokens(name=token_name).get("_id")

        return self.ms.patch(
            f"/crm/v1/access-tokens/{token_id}",
            accepted_status=[requests.codes.ok],
        ).json()

    def unblock_access_token_brute_force(self, ip_address: str = "", token_id: str = "") -> None:
        """Unblock access token brute-force state.

        Removes brute-force block state for either an IP address or an access token identifier.
        Exactly one of the two parameters must be provided.

        Parameters
        ----------
        ip_address : str, optional
            IPv4 address whose access-token brute-force block state should be removed.
        token_id : str, optional
            Access token identifier whose brute-force block state should be removed.
        """
        if not ip_address and not token_id:
            msg = "ip_address or token_id must be provided"
            raise ValueError(msg)
        if ip_address and token_id:
            msg = "Only one of ip_address or token_id may be provided"
            raise ValueError(msg)

        payload = {"ipAddress": ip_address} if ip_address else {"tokenId": token_id}

        self.ms.post(
            "/crm/v1/access-tokens/brute-force/unblock",
            json=payload,
            accepted_status=[requests.codes.no_content],
        )

    def delete_access_token(self, token_id: str = "", token_name: str = "") -> bool:
        """Delete API access token for authenticated user.

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
        """
        if not token_id and not token_name:
            msg = "token_id or token_name must be provided"
            raise ValueError(msg)

        if not token_id:
            token_id = self.get_access_tokens(name=token_name).get("_id")

        self.ms.delete(
            f"/crm/v1/access-tokens/{token_id}",
            accepted_status=[requests.codes.no_content],
        )
        return True


class LocalUser:
    """User management related functions from MS.

    Parameters
    ----------
    node_handle :
        node handle 'nerve_lib.general_utils.NodeHandle(...)'.
    """

    def __init__(self, node_handle):
        self.node = node_handle
        self._log = node_handle._log.getChild("User")

    def delete(self, username: str = ""):
        """Delete all users or a specific user from the node.

        Parameters
        ----------
        user : str, optional
            username to delete. The default is None which will delete all users.

        Returns
        -------
        type
            response from the node.
        """
        if username:
            return self.node.delete("/api/users", params={"username": username})
        return self.node.delete("/api/users")

    def get(self, username: str = ""):
        """Get all users or a specific user from the node."""
        if username:
            return self.node.get("/api/users", params={"username": username})
        return self.node.get("/api/users")

    def user_exists(self, username: str) -> bool:
        """Check if a specific user exists.

        Parameters
        ----------
        username : str
            username to check.

        Returns
        -------
        bool
            True if the user exists, False otherwise.
        """
        response = self.get()
        if response.status_code in {requests.codes.ok, requests.codes.accepted, requests.codes.no_content}:
            users = response.json().get("users", [])
            return any(user["username"] == username for user in users)
        return False


class LDAP:
    """LDAP management related functions from MS.

    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.
    """

    def __init__(self, ms_handle):
        self.ms = ms_handle

    def check_active(self):
        """Check if LDAP is active."""
        return self.ms.get(
            "/nerve/ldap/active", accepted_status=[requests.codes.ok], timeout=(7.5, 30)
        ).json()

    def get_default(self):
        """Get default LDAP configuration."""
        response = self.ms.get(
            "/nerve/ldap/default", accepted_status=[requests.codes.ok, requests.codes.no_content]
        )
        if response.status_code == requests.codes.no_content:
            return None
        return response.json()

    def get_config(self):
        """Get LDAP configuration details."""
        return self.ms.get("/nerve/ldap", accepted_status=[requests.codes.ok]).json()

    def enable_disable_ldap(self, enable: bool):
        """Activate LDAP configuration."""
        return self.ms.patch(
            "/nerve/ldap/ldap_config/active", json={"active": enable}, accepted_status=[requests.codes.ok]
        ).json()

    def test_connection(
        self,
        url: str,
        port=389,
        bind_dn="",
        password="",  # nosec B107
        secure=False,
    ):
        """Test LDAP server connection.

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
        """
        payload = {"url": url, "port": port, "bindDN": bind_dn, "password": password, "tls": secure}
        return self.ms.post(
            "/nerve/ldap/connection/test",
            json=payload,
            accepted_status=[requests.codes.ok],
            timeout=(7.5, 10),
        ).json()

    @classmethod
    def recurring_sync(cls, recurring_sync=False, schedule="", time=""):
        """Set recurring sync details.

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
        """
        if recurring_sync is False:
            return {"recurringSync": recurring_sync}
        return {"recurringSync": recurring_sync, "schedule": schedule, "time": time}

    @classmethod
    def relationship(cls, type="group-user", membership="", target=""):
        """Set relationship details.

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
        """
        return {"type": type, "membership": membership, "target": target}

    @classmethod
    def users(cls, search_base="", filter="", first_name="", last_name="", email="", username=""):
        """Set users details.

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
        """
        return {
            "searchBase": search_base,
            "filter": filter,
            "firstName": first_name,
            "lastName": last_name,
            "email": email,
            "username": username,
        }

    @classmethod
    def groups(cls, search_base="", filter="", group_name="", admin_group="", default_role=""):
        """Set groups details.

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
        """
        return {
            "searchBase": search_base,
            "filter": filter,
            "name": group_name,
            "adminGroup": admin_group,
            "default": default_role,
        }

    def ldap_payload(
        self,
        url: str,
        file_name: str = "",
        name: str = "ldap_config",
        port: int = 389,
        active: bool = False,
        bind_dn: str = "",
        password: str = "",  # nosec B107
        tls: bool = False,
        recurring_sync=None,
        relationship=None,
        users=None,
        groups=None,
    ):
        """Set LDAP configuration payload.

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
        """
        recurring_sync = recurring_sync or self.recurring_sync()
        relationship = relationship or self.relationship()
        users = users or self.users()
        groups = groups or self.groups()

        if users == "0":
            return {
                "fileName": file_name,
                "name": name,
                "url": url,
                "port": port,
                "active": active,
                "bindDN": bind_dn,
                "password": password,
                "tls": tls,
                "recurringSync": recurring_sync,
                "relationship": relationship,
                "groups": groups,
            }
        if groups == "0":
            return {
                "fileName": file_name,
                "name": name,
                "url": url,
                "port": port,
                "active": active,
                "bindDN": bind_dn,
                "password": password,
                "tls": tls,
                "recurringSync": recurring_sync,
                "relationship": relationship,
                "users": users,
            }

        return {
            "fileName": file_name,
            "name": name,
            "url": url,
            "port": port,
            "active": active,
            "bindDN": bind_dn,
            "password": password,
            "tls": tls,
            "recurringSync": recurring_sync,
            "relationship": relationship,
            "users": users,
            "groups": groups,
        }

    def query_groups(
        self, password, search_base="", filter="", group_name="", admin_group="", default_role=""
    ):
        """Query groups from LDAP configuration.

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
        """
        group_payload = self.groups(search_base, filter, group_name, admin_group, default_role)
        ldap_payload = self.get_default()
        ldap_payload["fileName"] = ldap_payload["file"]
        ldap_payload.pop("file", None)
        ldap_payload.pop("initiator", None)
        ldap_payload.pop("urlInfo", None)
        ldap_payload.pop("users", None)

        ldap_payload["groups"] = group_payload
        ldap_payload["password"] = password
        payload = {"ldap": ldap_payload, "paging": {"limit": 10, "page": 1}}
        return self.ms.post(
            "/nerve/ldap/query/groups", json=payload, accepted_status=[requests.codes.ok]
        ).json()

    def query_users(
        self, password, search_base="", filter="", first_name="", last_name="", email="", username=""
    ):
        """Query users from LDAP configuration.

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
        """
        user_payload = self.users(search_base, filter, first_name, last_name, email, username)

        ldap_payload = self.get_default()
        ldap_payload["fileName"] = ldap_payload["file"]
        ldap_payload.pop("file", None)
        ldap_payload.pop("initiator", None)
        ldap_payload.pop("urlInfo", None)
        ldap_payload.pop("groups", None)

        ldap_payload["users"] = user_payload
        ldap_payload["password"] = password
        payload = {"ldap": ldap_payload, "paging": {"limit": 10, "page": 1}}
        return self.ms.post(
            "/nerve/ldap/query/users", json=payload, accepted_status=[requests.codes.ok]
        ).json()

    def set_ldap_state(self, state: bool, name: str):
        """Set LDAP state.

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
        """
        payload = {"active": state}
        return self.ms.patch(
            f"/nerve/ldap/{name}/active", json=payload, accepted_status=[requests.codes.ok]
        ).json()

    def save_sync_ldap(
        self,
        action: str,
        file_name: str,
        ldap_payload: dict,
    ):
        """
        Send LDAP configuration payload with populated data from other functions.

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
        """
        if action == "save":
            # Send the POST request
            return self.ms.post("/nerve/ldap", json=ldap_payload, accepted_status=[requests.codes.ok]).json()
        if action == "update":
            # Send the PUT request
            return self.ms.put(
                f"/nerve/ldap/{file_name}", json=ldap_payload, accepted_status=[requests.codes.ok]
            ).json()
        if action == "sync":
            # Send the POST request
            return self.ms.post(
                "/nerve/ldap/sync", json=ldap_payload, accepted_status=[requests.codes.ok]
            ).json()

        err_msg = f"Invalid action for function save_sync_ldap: {action}"
        raise ValueError(err_msg)
