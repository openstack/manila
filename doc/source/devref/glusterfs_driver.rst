..
      Copyright 2015 Red Hat, Inc.
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

GlusterFS driver
================

GlusterFS driver uses GlusterFS, an open source distributed file system,
as the storage backend for serving file shares to Manila clients.

Supported shared filesystems
----------------------------

- NFS (access by IP)


Supported Operations
--------------------

- Create NFS Share
- Delete NFS Share
- Allow NFS Share access
- Deny NFS Share access

Requirements
------------

- Install glusterfs-server package, version >= 3.5.x, on the storage backend.
- Install glusterfs and glusterfs-fuse package, version >=3.5.x, on the Manila
  host.
- Establish network connection between the Manila host and the storage backend.


Manila driver configuration setting
-----------------------------------

The following parameters in the Manila's configuration file need to be
set:

- `share_driver` = manila.share.drivers.glusterfs.GlusterfsShareDriver
- If the backend GlusterFS server runs on the Manila host machine,
   - `glusterfs_target` = <glustervolserver>:/<glustervolid>
  And if the backend GlusterFS server runs remotely,
   -  `glusterfs_target` = <username>@<glustervolserver>:/<glustervolid>

The following configuration parameters are optional:

- `glusterfs_mount_point_base` =  <base path of GlusterFS volume mounted on
     Manila host>
- `glusterfs_path_to_private_key` = <path to Manila host's private key file>
- `glusterfs_server_password` = <password of remote GlusterFS server machine>


Known Restrictions
------------------

- The driver does not support network segmented multi-tenancy model instead
  works over a flat network, where the tenants share a network.
- NFSv3 is the only protocol that can be used to access the shares. This is
  because the shares are mediated in the backend GlusterFS by the Gluster-NFS
  server that supports only NFSv3 protocol.
- All Manila shares, which map to subdirectories within a GlusterFS volume, are
  currently created within a single GlusterFS volume of a GlusterFS storage
  pool.

The :mod:`manila.share.drivers.glusterfs` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.glusterfs
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
