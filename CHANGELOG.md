# Changelog

## 1.5.0
- Added support for logging in to the Management System with an access token instead of username/password:
  - `MSHandle` now accepts an `access_token` argument (or `MS_ACCESS_TOKEN` env-var), which takes priority
    over username/password and skips the regular login/logout flow.
- Added access token management functions to `MSUser`: `create_access_token`, `delete_access_token`,
  `get_access_tokens`, and `unblock_access_token_brute_force` (to unblock the brute-force protection of a token).
- Added `get_user_permissions` function to `MSUser` to list all permissions available to a user.
- Added `get_access_token_creation_permissions` function to `MSUser` to list all possible permissions for creating an access token.
- Added label management functions for nodes to `MSLabel`: `get_node_labels`, `add_node_label`,
  `del_node_label`, `edit_node_label`, `export_node_labels`, and `import_node_labels`.
- Added compose-restrictions management functions for nodes to `MSNode`: `get_compose_restrictions`,
  `get_compose_restrictions_version`, and `update_compose_restrictions`.

## 1.4.0
- Added new function for 3.2.0 release, updated API endpoints
- Refactored workload template creation for internal-docker-registry
- Refactored ldpa functions
- Fixed issue to download DNA content
- Added filter for node-name / node-serial to decrease get_nodes response time
- General Bugfixing and code cleanup

## 1.3.0
- Added support for filtering workloads by type in `get_workloads_dict` function

## 1.2.0
- Update library version, refactored ssh-tunnel creation and MultipartEncode requests
- Changed logging name, extending name with child to refect relations better
- Code cleanup, Removed internal test functions

## 1.1.0
- Updated DNA endpoints for new release
- Added Service OS DNA endpoint for new releaes
- Refactored Login/Logout to MS and nodes, to automatically logout when the class handle is removed
- Added functions to set new login-credentials (also for SSH)
- Updated function for setting language for new release
- Fixed issue in edit user function
- Fixed LDAP functions
- Fixed issue in deploy_full function
- Fixed issue with recursive login loop
- Fixed manage_node remove_unused_images function
- Fixed timing issus
- Updated MS endpoint '/nerve/update/local-node-update' (get_possible_updates) for new release
- Added function to onboard/offboard nodes with new release

## 1.0.0
- Initial version
