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

GlusterFS Native driver
=======================

GlusterFS Native driver uses GlusterFS, an open source distributed file system,
as the storage backend for serving file shares to Manila clients.

A Manila share is a GlusterFS volume. This driver uses flat-network
(share-server less) model.  Instances directly talk with the GlusterFS backend
storage pool. The instances use 'glusterfs' protocol to mount the GlusterFS
shares. Access to each share is allowed via TLS Certificates. Only the instance
which has the TLS trust established with the GlusterFS backend can mount and
hence use the share. Currently only 'rw' access is supported.

Network Approach
----------------

L3 connectivity between the storage backend and the host running the Manila
share service should exist.

Supported shared filesystems
----------------------------

- GlusterFS (access by TLS Certificates (``cert`` access type))

Multi-tenancy model
-------------------

The driver does not support network segmented multi-tenancy model. Instead
multi-tenancy is supported using tenant specific TLS certificates.

Supported Operations
--------------------

- Create GlusterFS Share
- Delete GlusterFS Share
- Allow GlusterFS Share access (rw)
- Deny GlusterFS Share access

Requirements
------------

- Install glusterfs-server package, version >= 3.6.x, on the storage backend.
- Install glusterfs and glusterfs-fuse package, version >=3.6.x, on the Manila
  host.
- Establish network connection between the Manila host and the storage backend.


Manila driver configuration setting
-----------------------------------

The following parameters in Manila's configuration file need to be set:

- `share_driver` =
    manila.share.drivers.glusterfs_native.GlusterfsNativeShareDriver
- `glusterfs_targets` = List of GlusterFS volumes that can be used to create
     shares. Each GlusterFS volume should be of the form
       ``[remoteuser@]<glustervolserver>:/<glustervolid>``

If the backend GlusterFS server runs on the host running the Manila share
service, each member of the `glusterfs_targets` list can be of the form
``<glustervolserver>:/<glustervolid>``

If the backend GlusterFS server runs remotely, each member of the
`glusterfs_targets` list can be of the form
``<remoteuser>@<glustervolserver>:/<glustervolid>``

The following configuration parameters are optional:

- `glusterfs_mount_point_base` =  <base path of GlusterFS volume mounted on
     Manila host>
- `glusterfs_path_to_private_key` = <path to Manila host's private key file>
- `glusterfs_server_password` = <password of remote GlusterFS server machine>


Known Restrictions
------------------

- GlusterFS volumes are not created on the fly. A pre-existing list of
  GlusterFS volumes must be supplied in `glusterfs_targets`.
- Certificate setup (aka trust setup) between instance and storage backend is
  out of band of Manila.
- Support for 'create_snapshot' and 'create_share_from_snapshot' is planned for Liberty release.

The :mod:`manila.share.drivers.glusterfs_native.GlusterfsNativeShareDriver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.glusterfs_native
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
