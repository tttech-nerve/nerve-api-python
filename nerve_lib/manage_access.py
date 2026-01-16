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
import logging
import re
from typing import Optional

import requests
import yaml
from requests_toolbelt import MultipartEncoder


class MSRole:
    """Role management related functions from MS.

    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.
    """

    def __init__(self, ms_handle):
        self.ms = ms_handle
        self._log = logging.getLogger("Role")

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
            raise Exception(
                msg,
            )

    def get_permission_ui(self, name_filter: str = ""):
        """Get list of permissions for UI class."""
        return self.ms.get(
            "/nerve/rbac/permissions",
            params={"categories": "UI_PERMISSION", "filterBy": f'{{"name":"{name_filter}"}}'},
            accepted_status=[requests.codes.ok],
        ).json()

    def get_permission_api(self, name_filter: str = ""):
        """Get list of permissions for all classes (API)."""
        return self.ms.get(
            "/nerve/rbac/permissions",
            params={"categories": "", "filterBy": f'{{"name":"{name_filter}"}}'},
            accepted_status=[requests.codes.ok],
        ).json()

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
                raise Exception(
                    msg,
                )
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
                raise Exception(
                    msg,
                )

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
        self._log = logging.getLogger("User")
        self._role = MSRole(ms_handle)

    def get(self, email="", role_type="local"):
        """Get a list of users."""
        user_list = self.ms.get(
            "/crm/profile/list",
            params=[{"filterBy[type]", role_type}],
            accepted_status=[requests.codes.ok],
        ).json()
        if email:
            try:
                return next(user for user in user_list["data"] if user["username"] == email)
            except StopIteration:
                msg = (
                    f"User '{email}' not in role_type '{role_type}' "
                    f"({[user['username'] for user in user_list['data']]}"
                )
                raise Exception(
                    msg,
                )
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

        role_ids = []
        for role in roles:
            role_ids.append(self._role.get(role, role_type)["_id"])

        payload = {
            "firstName": first_name or uname[0],
            "lastName": last_name or uname[-1],
            "username": email,
            "profileImgURL": "",
            "contact": [
                {
                    "contactType": "email",
                    "isDefault": True,
                    "label": "Default",
                    "contact": email,
                    "email": "",
                },
            ],
            "roles": role_ids,
        }
        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        while True:
            m_enc = MultipartEncoder({"data": (None, json.dumps(payload), "form-data")})

            response = self.ms.post(
                "/crm/profile",
                data=m_enc,
                content_type=m_enc.content_type,
                accepted_status=accepted_status,
            )
            if response.status_code == requests.codes.forbidden:
                self.node.login()
                accepted_status = [requests.codes.ok]
                continue
            break
        return response.json()

    def edit(self, email: str, roles: list = [], first_name="", last_name="", role_type="local"):
        """Edit an existing user."""
        payload = self.get(email, role_type)

        if roles:
            role_ids = []
            for role in roles:
                role_ids.append(self._role.get(role, role_type)["_id"])
            payload["roles"] = role_ids

        if first_name:
            payload["firstName"] = first_name

        if last_name:
            payload["lastName"] = last_name

        payload["profileImgURL"] = ""

        payload["id"] = payload.pop("_id")

        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        while True:
            m_enc = MultipartEncoder({"data": (None, json.dumps(payload), "form-data")})

            response = self.ms.put(
                f"/crm/profile/{payload.get('id')}",
                data=m_enc,
                content_type=m_enc.content_type,
                accepted_status=accepted_status,
            )
            if response.status_code == requests.codes.forbidden:
                self.node.login()
                accepted_status = [requests.codes.ok]
                continue
            break
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
        confirm_new_password="",
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
            "profileImgURL": "",
            "contact": [
                {
                    "contactType": "email",
                    "isDefault": True,
                    "label": "Default",
                    "contact": email,
                    "email": email,
                },
            ],
            "currentPassword": old_password,
            "newPassword": new_password,
            "confirmPassword": confirm_new_password,
        }

        accepted_status = [requests.codes.ok, requests.codes.forbidden]
        while True:
            m_enc = MultipartEncoder({"data": (None, json.dumps(payload), "form-data")})

            response = self.ms.put(
                "/crm/personalProfile",
                data=m_enc,
                content_type=m_enc.content_type,
                accepted_status=accepted_status,
            )
            if response.status_code == requests.codes.forbidden:
                self.node.login()
                accepted_status = [requests.codes.ok]
                continue
            break
        return response.json()

    def extract_endpoints(self, openapi_spec, output_json):
        """Extract endpoints from OpenAPI specification and save to JSON file."""
        try:
            with open(openapi_spec, "r", encoding="utf-8") as file:
                if ".yml" in openapi_spec or ".yaml" in openapi_spec:
                    data = yaml.safe_load(file)
                elif ".json" in openapi_spec:
                    data = json.load(file)
                else:
                    self._log.error("API spec file format not supported!")

                # Extract endpoints from paths and save to JSON file
                if "paths" in data:
                    paths = data["paths"]
                    endpoints = []

                    for path, methods in paths.items():
                        endpoint_data = {"Endpoint": path, "Methods": list(methods.keys())}
                        endpoints.append(endpoint_data)

                    with open(output_json, "w", encoding="utf-8") as json_file:
                        json.dump(endpoints, json_file, indent=2)
                    self._log.info("Endpoints saved to %s", output_json)
                else:
                    msg = "No 'paths' field found in the OpenAPI specification."
                    raise ValueError(msg)

        except FileNotFoundError:
            self._log.error("File not found: %s", output_json)
        except yaml.YAMLError:
            self._log.error("Invalid YAML format in file: %s", openapi_spec)
        except json.JSONDecodeError:
            self._log.exception("JSON decoding error")
        except Exception:
            self._log.exception("An error occurred")


class LocalUser:
    """User management related functions from MS.

    Parameters
    ----------
    ms_handle :
        management system handle 'nerve_lib.general_utils.MSHandle(...)'.
    """

    def __init__(self, node_handle):
        self.node = node_handle
        self._log = logging.getLogger("User")

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
        self, url: str, port=389, bind_dn="cn=admin,dc=tttech,dc=com", password="Passw0rd", secure=False
    ):
        """Test LDAP server connection.

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
        return {"recurringSync": recurring_sync, "schedule": schedule, "time": time}

    @classmethod
    def relationship(cls, type="", membership="", target=""):
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
        file_name: str = "",
        name: str = "ldap_config",
        url: str = "ldap.dev.nerve.cloud",
        port: int = 389,
        active: bool = False,
        bind_dn: str = "cn=admin,dc=tttech,dc=com",
        password: str = "Passw0rd",
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

    def query_groups(self, search_base="", filter="", group_name="", admin_group="", default_role=""):
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
        ldap_payload = self.ldap_payload(users="0", groups=group_payload)
        payload = {"ldap": ldap_payload, "paging": {"limit": 10, "page": 1}}
        return self.ms.post(
            "/nerve/ldap/query/groups", json=payload, accepted_status=[requests.codes.ok]
        ).json()

    def query_users(self, search_base="", filter="", first_name="", last_name="", email="", username=""):
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
        ldap_payload = self.ldap_payload(users=user_payload, groups="0")
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
        ldap_payload: Optional[dict] = None,
        recurring_sync=None,
        relationship=None,
        users=None,
        groups=None,
    ):
        """
        Send LDAP configuration payload with populated data from other functions.

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
        """
        # Populate each component of the payload if not provided
        recurring_sync = recurring_sync or self.recurring_sync()
        relationship = relationship or self.relationship()
        users = users or self.users()
        groups = groups or self.groups()

        # Create the full LDAP payload
        payload = ldap_payload or self.ldap_payload(
            file_name=file_name,
            name=file_name,
            recurring_sync=recurring_sync,
            relationship=relationship,
            users=users,
            groups=groups,
        )

        if action == "save":
            # Send the POST request
            return self.ms.post("/nerve/ldap", json=payload, accepted_status=[requests.codes.ok]).json()
        if action == "update":
            # Send the PUT request
            return self.ms.put(
                f"/nerve/ldap/{file_name}", json=payload, accepted_status=[requests.codes.ok]
            ).json()
        if action == "sync":
            # Send the POST request
            return self.ms.post("/nerve/ldap/sync", json=payload, accepted_status=[requests.codes.ok]).json()

        err_msg = f"Invalid action for function save_sync_ldap: {action}"
        raise ValueError(err_msg)


class InternalTestAPI:
    """Manage Internal Test API related functions. NOT FOR PRODUCTION USE!"""

    def __init__(self, ms_handle):
        self.ms = ms_handle
        self.base_path = "/nerve/internal-test-api/"

    def get_value(self, parameter: str):
        """Get a specific configuration value.

        Parameters
        ----------
        parameter : str
            Name of the top-level key in the configuration.yaml file.

        Returns
        -------
        type
            Configuration value for the specified parameter.
        """
        return self.ms.get(
            f"{self.base_path}config/{parameter}", accepted_status=[requests.codes.ok], timeout=(7.5, 30)
        ).json()

    def reset_value(self, parameter: str, configuration: str):
        """Reset a specific configuration value to its default.

        Parameters
        ----------
        parameter : str
            Name of the top-level key in the configuration.yaml file.

        Returns
        -------
        type
            Response from the reset request.
        """
        self.ms.post(
            f"{self.base_path}config/{parameter}/reload",
            json={"config": configuration},
            accepted_status=[requests.codes.ok],
            timeout=(7.5, 30),
        )
        return self.get_value(parameter)

    def set_value(self, parameter: str, configuration: json):
        """Set a specific configuration value.

        Parameters
        ----------
        parameter : str
            Name of the top-level key in the configuration.yaml file.

        Returns
        -------
        type
            Response from the set request.
        """
        self.ms.patch(
            f"{self.base_path}config/{parameter}",
            json={"config": configuration},
            accepted_status=[requests.codes.accepted],
            timeout=(7.5, 30),
        )
        return self.get_value(parameter)
