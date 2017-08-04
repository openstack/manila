..
      Copyright (c) 2016 Mirantis Inc.
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

ZFS (on Linux) Driver
=====================

Manila ZFSonLinux share driver uses ZFS filesystem for exporting NFS shares.
Written and tested using Linux version of ZFS.

Requirements
------------

* 'NFS' daemon that can be handled via "exportfs" app.
* 'ZFS' filesystem packages, either Kernel or FUSE versions.
* ZFS zpools that are going to be used by Manila should exist and be
  configured as desired. Manila will not change zpool configuration.
* For remote ZFS hosts according to manila-share service host SSH should be
  installed.
* For ZFS hosts that support replication:
   * SSH access for each other should be passwordless.
   * Service IP addresses should be available by ZFS hosts for each other.

Supported Operations
--------------------

The following operations are supported:

* Create NFS Share
* Delete NFS Share
* Manage NFS Share
* Unmanage NFS Share
* Allow NFS Share access
   * Only IP access type is supported for NFS
   * Both access levels are supported - 'RW' and 'RO'
* Deny NFS Share access
* Create snapshot
* Delete snapshot
* Manage snapshot
* Unmanage snapshot
* Create share from snapshot
* Extend share
* Shrink share
* Replication (experimental):
   * Create/update/delete/promote replica operations are supported
* Share migration (experimental)

Possibilities
-------------

* Any amount of ZFS zpools can be used by share driver.
* Allowed to configure default options for ZFS datasets that are used
  for share creation.
* Any amount of nested datasets is allowed to be used.
* All share replicas are read-only, only active one is RW.
* All share replicas are synchronized periodically, not continuously.
  So, status 'in_sync' means latest sync was successful.
  Time range between syncs equals to value of
  config global opt 'replica_state_update_interval'.
* Driver is able to use qualified extra spec 'zfsonlinux:compression'.
  It can contain any value that is supported by used ZFS app.
  But if it is disabled via config option with value 'compression=off',
  then it will not be used.

Restrictions
------------

The ZFSonLinux share driver has the following restrictions:

* Only IP access type is supported for NFS.
* Only FLAT network is supported.
* 'Promote share replica' operation will switch roles of
  current 'secondary' replica and 'active'. It does not make more than
  one active replica available.
* 'SaMBa' based sharing is not yet implemented.
* 'Thick provisioning' is not yet implemented.

Known problems
--------------

* 'Promote share replica' operation will make ZFS filesystem that became
  secondary as RO only on NFS level. On ZFS level system will
  stay mounted as was - RW.

Backend Configuration
---------------------

The following parameters need to be configured in the manila configuration file
for the ZFSonLinux driver:

* share_driver = manila.share.drivers.zfsonlinux.driver.ZFSonLinuxShareDriver
* driver_handles_share_servers = False
* replication_domain = custom_str_value_as_domain_name
   * if empty, then replication will be disabled
   * if set then will be able to be used as replication peer for other
     backend with same value.
* zfs_share_export_ip = <user_facing IP address of ZFS host>
* zfs_service_ip = <IP address of service network interface of ZFS host>
* zfs_zpool_list = zpoolname1,zpoolname2/nested_dataset_for_zpool2
   * can be one or more zpools
   * can contain nested datasets
* zfs_dataset_creation_options = <list of ZFS dataset options>
   * readonly,quota,sharenfs and sharesmb options will be ignored
* zfs_dataset_name_prefix = <prefix>
   * Prefix to be used in each dataset name.
* zfs_dataset_snapshot_name_prefix = <prefix>
   * Prefix to be used in each dataset snapshot name.
* zfs_use_ssh = <boolean_value>
   * set 'False' if ZFS located on the same host as 'manila-share' service
   * set 'True' if 'manila-share' service should use SSH for ZFS configuration
* zfs_ssh_username = <ssh_username>
   * required for replication operations
   * required for SSH'ing to ZFS host if 'zfs_use_ssh' is set to 'True'
* zfs_ssh_user_password = <ssh_user_password>
   * password for 'zfs_ssh_username' of ZFS host.
   * used only if 'zfs_use_ssh' is set to 'True'
* zfs_ssh_private_key_path = <path_to_private_ssh_key>
   * used only if 'zfs_use_ssh' is set to 'True'
* zfs_share_helpers = NFS=manila.share.drivers.zfsonlinux.utils.NFSviaZFSHelper
   * Approach for setting up helpers is similar to various other share driver
   * At least one helper should be used.
* zfs_replica_snapshot_prefix = <prefix>
   * Prefix to be used in dataset snapshot names that are created
     by 'update replica' operation.
* zfs_migration_snapshot_prefix = <prefix>
   * Prefix to be used in dataset snapshot names that are created
     for 'migration' operation.

Restart of :term:`manila-share` service is needed for the configuration
changes to take effect.

The :mod:`manila.share.drivers.zfsonlinux.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.zfsonlinux.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`manila.share.drivers.zfsonlinux.utils` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.zfsonlinux.utils
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
