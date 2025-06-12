<p align="center">
    <img src="./img/logo-nerve-black.svg" alt="Nerve"/><br><br>
    <a href="./LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg"/></a>
    <a href="https://docs.python.org/3/"><img src="https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg"/></a>
    <a href="https://docs.nerve.cloud"><img src="https://img.shields.io/badge/nerve-2.9%20%7C%202.10%20%7C%203.0-blue.svg"/></a>
</p>

The *nerve_lib* provides an interface to the REST API of a [Nerve Management System](https://docs.nerve.cloud/) in python. It implements authentication, and management of nodes and workloads. The *nerve_lib* can be used to integrate Nerve related tasks into a build pipeline (e.g. automatically creating a workload and deploying it on a test node when a new version of an application image is built).

# Table of Contents
- <a href="#h_installation">Installation</a>
    - <a href="#hh_poetry">Poetry</a>
    - <a href="#hh_manual">Manual</a>
- <a href="#h_usage">Documentation</a>
    - <a href="#hh_overview">Overview</a>
    - <a href="#hh_examples">Examples</a>

# Installation<a name="h_installation"></a>

To use the *nerve_lib* in a python project it has to be installed fist. The easiest way to do so is to add the dependency with poetry. If poetry is not used, the library can be added by copying the files and adding the dependencies.

## Poetry<a name="hh_poetry"></a>

The *nerve_lib* is implemented as a [poetry](https://python-poetry.org/) package. Poetry is a project and dependency management tool for python. Refer to the [poetry documentation](https://python-poetry.org/) for more information on how to install poetry and how to use it to manage a python project. 

To add the *nerve_lib* to your python project with poetry simply add the dependency with
```bash
poetry add git+https://github.com/tttech-nerve/nerve-api-python.git
```
and then install it into the environment with
```bash
poetry install
```

## Manual<a name="hh_manual"></a>

If the python project or script is not managed by poetry, the [*nerve_lib*](./nerve_lib) folder must be copied into the project tree. Furthermore the dependencies as listed in [`requirements.txt`](./requirements.txt) must be installed in the python environment of the project
```bash
pip install -r requirements.txt
```

# Usage<a name="h_usage"></a>

The *nerve_lib* provides functions to manage the NERVE Management System and NERVE Nodes via API calls. It is split into different regions to define API interfaces into logical groups. [Overview](#hh_overview) and [Examples](#hh_examples) provide a very rough guideline on how to use the library. For details have a look at the code [documentation](./docs/markdown/index.md). A more interactive version of the documentation is available by cloning the repository and opening [docs/html/index.html](./docs/html/index.html) in a browser.

## Overview<a name="hh_overview"></a>
| Handle           | Description                                           |
|------------------|-------------------------------------------------------|
| setup_logging    | Defines a common logging schema. The function is automatically called when using `MSHandle` or `NodeHandle`. |
| CheckStatusCodeError | When API functions are used, the returned status code is evaluated. An invalid code will raise this error type. |
| WorkloadDeployError | Handles errors during workload deployment. |
| NodeHandle       | Provides functionality to manage local nodes. |
| MSHandle         | Manages the NERVE Management System. |
| MSWorkloads      | Manages workloads in the Management System. |
| LocalWorkloads   | Manages workloads on local nodes. |
| MSNode           | Represents a node in the Management System. |
| LocalNode        | Represents a local node. |
| MSUser           | Manages users in the Management System. |
| MSRole           | Manages roles in the Management System. |
| LocalUser        | Manages users on the local node. |
| LDAP             | Provides LDAP-related functionality. |
| MSDNA            | Manages DNA configurations in the Management System. |
| LocalDNA         | Manages DNA configurations on the local node. |
| MSLabel          | Manages labels in the Management System. |
| MSNotifications  | Handles notifications in the Management System. |
| MSOpenSearch     | Provides OpenSearch-related API interface. |
| InternalRegistry | Manages the internal registry in the Management System. |
| DockerVolumes    | Manages Docker volumes in the Management System. |

## Examples<a name="hh_examples"></a>

**Provision a new workload**
```python
from nerve_lib import MSHandle
from nerve_lib import MSWorkloads

with MSHandle("testms.nerve.cloud", "ms-username", "ms-password") as ms_handle:
    wl = MSWorkloads(ms_handle)
    wl_config = wl.gen_workload_configuration(
        "docker",
        wrkld_name="docker",
        file_paths=["docker.tar"],
        restart_policy="always"
    )
    wl.provision_workload(wl_config, file_paths=["images/docker.tar"])
```

**Get dict of all nodes containing "MFN" in the name**
```python
from nerve_lib import MSHandle
from nerve_lib import MSNode

with MSHandle("testms.nerve.cloud", "ms-username", "ms-password") as ms_handle:
    nodes = MSNode(ms_handle)
    nodes.get_nodes_by_name("MFN")
```