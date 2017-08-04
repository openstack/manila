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
as the storage backend for serving file shares to manila clients.

Supported shared filesystems
----------------------------

- NFS (access by IP)


Supported Operations
--------------------

- Create share
- Delete share
- Allow share access (rw)
- Deny share access
- With volume layout:

  - Create snapshot
  - Delete snapshot
  - Create share from snapshot

Requirements
------------

- Install glusterfs-server package, version >= 3.5.x, on the storage backend.
- Install NFS-Ganesha, version >=2.1, if using NFS-Ganesha as the NFS server
  for the GlusterFS backend.
- Install glusterfs and glusterfs-fuse package, version >=3.5.x, on the manila
  host.
- Establish network connection between the manila host and the storage backend.


Manila driver configuration setting
-----------------------------------

The following parameters in the manila's configuration file need to be
set:

- `share_driver` = manila.share.drivers.glusterfs.GlusterfsShareDriver

The following configuration parameters are optional:

- `glusterfs_nfs_server_type` = <NFS server type used by the GlusterFS
     backend, `Gluster` or `Ganesha`. `Gluster` is the default type>
- `glusterfs_share_layout` = <share layout used>; cf. :ref:`glusterfs_layouts`
- `glusterfs_path_to_private_key` = <path to manila host's private key file>
- `glusterfs_server_password` = <password of remote GlusterFS server machine>

If Ganesha NFS server is used (``glusterfs_nfs_server_type = Ganesha``),
then by default the Ganesha server is supposed to run on the manila host
and is managed by local commands. If it's deployed somewhere else, then
it's managed via ssh, which can be configured by the following parameters:

- `glusterfs_ganesha_server_ip`
- `glusterfs_ganesha_server_username`
- `glusterfs_ganesha_server_password`

In lack of ``glusterfs_ganesha_server_password`` ssh access will fall
back to key based authentication, using the key specified by
``glusterfs_path_to_private_key``, or, in lack of that, a key at
one of the OpenSSH-style default key locations (*~/.ssh/id_{r,d,ecd}sa*).

For further (non driver specific) configuration of Ganesha, see
:doc:`ganesha`. It is recommended to consult with :doc:`ganesha`:
:ref:`ganesha_known_issues` too.

Layouts have also their set of parameters, see :ref:`glusterfs_layouts` about
that.

.. _glusterfs_layouts:

Layouts
-------

New in Liberty, multiple share layouts can be used with glusterfs
driver. A layout is a strategy of allocating storage from GlusterFS
backends for shares. Currently there are two layouts implemented:

- `directory mapped layout` (or `directory layout`, or `dir layout`
  for short): a share is backed by top-level subdirectories of a given
  GlusterFS volume.

  Directory mapped layout is the default and backward compatible with Kilo.
  The following setting explicitly specifies its usage:
  ``glusterfs_share_layout = layout_directory.GlusterfsDirectoryMappedLayout``.

  Options:

  - `glusterfs_target`: address of the volume that hosts the directories.
    If it's of the format `<glustervolserver>:/<glustervolid>`, then the
    manila host is expected to be part of the GlusterFS cluster of the volume
    and GlusterFS management happens through locally calling the ``gluster``
    utility. If it's of the format `<username>@<glustervolserver>:/<glustervolid>`,
    then we ssh to `<username>@<glustervolserver>` to execute ``gluster``
    (`<username>` is supposed to have administrative privileges on
    `<glustervolserver>`).
  - `glusterfs_mount_point_base` =  <base path of GlusterFS volume mounted on
     manila host> (optional; defaults to *$state_path*\ ``/mnt``, where
     *$state_path* defaults to ``/var/lib/manila``)

  Limitations:

  - directory layout does not support snapshot operations.

- `volume mapped layout` (or `volume layout`, or `vol layout` for short):
  a share is backed by a whole GlusterFS volume.

  Volume mapped layout is new in Liberty. It can be chosen by setting
  ``glusterfs_share_layout = layout_volume.GlusterfsVolumeMappedLayout``.

  Options (required):

  - `glusterfs_servers`
  - `glusterfs_volume_pattern`

  Volume mapped layout is implemented as a common backend of the glusterfs and
  glusterfs-native drivers; see the description of these options in
  :doc:`glusterfs_native_driver`: :ref:`gluster_native_manila_conf`.

Gluster NFS with volume mapped layout
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A special configuration choice is

::

    glusterfs_nfs_server_type = Gluster
    glusterfs_share_layout = layout_volume.GlusterfsVolumeMappedLayout

that is, Gluster NFS used to export whole volumes.

All other GlusterFS backend configurations (including GlusterFS set up
with glusterfs-native) require the ``nfs.export-volumes = off``
GlusterFS setting. Gluster NFS with volume layout requires
``nfs.export-volumes = on``. ``nfs.export-volumes`` is a *cluster-wide*
setting, so a given GlusterFS cluster cannot host a share backend with
Gluster NFS + volume layout and other share backend configurations at
the same time.

There is another caveat with ``nfs.export-volumes``: setting it to ``on``
without enough care is a security risk, as the default access control
for the volume exports is "allow all". For this reason, while the
``nfs.export-volumes = off`` setting is automatically set by manila
for all other share backend configurations, ``nfs.export-volumes = on``
is *not* set by manila in case of a Gluster NFS with volume layout
setup. It's left to the GlusterFS admin to make this setting in conjunction
with the associated safeguards (that is, for those volumes of the cluster
which are not used by manila, access restrictions have to be manually
configured through the ``nfs.rpc-auth-{allow,reject}`` options).

Known Restrictions
------------------

- The driver does not support network segmented multi-tenancy model, but
  instead works over a flat network, where the tenants share a network.
- If NFS Ganesha is the NFS server used by the GlusterFS backend, then the
  shares can be accessed by NFSv3 and v4 protocols. However, if Gluster NFS is
  used by the GlusterFS backend, then the shares can only be accessed by NFSv3
  protocol.
- All manila shares, which map to subdirectories within a GlusterFS volume, are
  currently created within a single GlusterFS volume of a GlusterFS storage
  pool.
- The driver does not provide read-only access level for shares.
- Assume that share S is exported through Gluster NFS, and tenant machine T
  has mounted S. If at this point access of T to S is revoked through
  `access-deny`, the pre-existing mount will be still usable and T will still
  be able to access the data in S as long as that mount is in place.
  (This violates the principle *Access deny should always result
  in immediate loss of access to the share*, see
  http://lists.openstack.org/pipermail/openstack-dev/2015-July/069109.html.)

The :mod:`manila.share.drivers.glusterfs` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.glusterfs
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
