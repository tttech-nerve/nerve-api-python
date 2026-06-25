# Changelog

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
