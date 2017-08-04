..
      Copyright 2015 IBM Corp.
      All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

GPFS Driver
===========

GPFS driver uses IBM General Parallel File System (GPFS), a high-performance,
clustered file system, developed by IBM, as the storage backend for serving
file shares to the manila clients.

Supported shared filesystems
----------------------------

- NFS (access by IP)


Supported Operations
--------------------

- Create NFS Share
- Delete NFS Share
- Create Share Snapshot
- Delete Share Snapshot
- Create Share from a Share Snapshot
- Allow NFS Share access

  * Currently only 'rw' access level is supported

- Deny NFS Share access

Requirements
------------

- Install GPFS with server license, version >= 2.0, on the storage backend.
- Install Kernel NFS or Ganesha NFS server on the storage backend servers.
- If using Ganesha NFS, currently NFS Ganesha v1.5 and v2.0 are supported.
- Create a GPFS cluster and create a filesystem on the cluster, that will be
  used to create the manila shares.
- Enable quotas for the GPFS file system (`mmchfs -Q yes`).
- Establish network connection between the manila host and the storage backend.


Manila driver configuration setting
-----------------------------------

The following parameters in the manila configuration file need to be set:

- `share_driver` = manila.share.drivers.ibm.gpfs.GPFSShareDriver
- `gpfs_share_export_ip` = <IP to be added to GPFS export string>
- If the backend GPFS server is not running on the manila host machine, the
  following options are required to SSH to the remote GPFS backend server:

  - `gpfs_ssh_login` = <GPFS server SSH login name>

    and one of the following settings is required to execute commands over SSH:

  - `gpfs_ssh_private_key` = <path to GPFS server SSH private key for login>
  - `gpfs_ssh_password` = <GPFS server SSH login password>

The following configuration parameters are optional:

- `gpfs_mount_point_base` = <base folder where exported shares are located>
- `gpfs_nfs_server_type` = <KNFS|GNFS>
- `gpfs_nfs_server_list` = <list of the fully qualified NFS server names>
- `gpfs_ssh_port` = <ssh port number>
- `knfs_export_options` = <options to use when creating a share using kernel
                          NFS server>

Restart of :term:`manila-share` service is needed for the configuration changes to take
effect.

Known Restrictions
------------------

- The driver does not support a segmented-network multi-tenancy model but
  instead works over a flat network where the tenants share a network.
- While using remote GPFS node, with Ganesha NFS, 'gpfs_ssh_private_key' for
  remote login to the GPFS node must be specified and there must be a
  passwordless authentication already setup between the manila share service
  and the remote GPFS node.

The :mod:`manila.share.drivers.ibm.gpfs` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.ibm.gpfs
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
