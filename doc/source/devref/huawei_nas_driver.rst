..
      Copyright (c) 2015 Huawei Technologies Co., Ltd.
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

Huawei Driver
=============

Huawei NAS Driver is a plugin based the OpenStack Manila service. The Huawei NAS
Driver can be used to provide functions such as the share and snapshot for virtual
machines(instances) in OpenStack. Huawei NAS Driver enables the OceanStor V3 series
V300R002 storage system to provide only network filesystems for OpenStack.

Requirements
------------

- The OceanStor V3 series V300R002 storage system.
- The following licenses should be activated on V3 for File:
  * CIFS
  * NFS
  * HyperSnap License (for snapshot)

Supported Operations
--------------------

The following operations is supported on V3 storage:

- Create CIFS/NFS Share
- Delete CIFS/NFS Share
- Allow CIFS/NFS Share access

  * IP and USER access types are supported for NFS(ro/rw).
  * Only USER access type is supported for CIFS(ro/rw).
- Deny CIFS/NFS Share access
- Create snapshot
- Delete snapshot
- Manage CIFS/NFS share
- Support pools in one backend
- Extend share
- Shrink share
- Support multi RestURLs(<RestURL>)


Pre-Configurations on Huawei
----------------------------

1. Create a driver configuration file. The driver configuration file name must
be the same as the manila_huawei_conf_file item in the manila_conf configuration
file.

2. Configure Product.
Product indicates the storage system type. For the OceanStor V3 series V300R002
storage systems, the driver configuration file is as follows:

::

    <?xml version='1.0' encoding='UTF-8'?>
    <Config>
        <Storage>
            <Product>V3</Product>
            <LogicalPortIP>x.x.x.x</LogicalPortIP>
            <Port>abc;CTE0.A.H1</Port>
            <RestURL>https://x.x.x.x:8088/deviceManager/rest/;
            https://x.x.x.x:8088/deviceManager/rest/</RestURL>
            <UserName>xxxxxxxxx</UserName>
            <UserPassword>xxxxxxxxx</UserPassword>
        </Storage>
        <Filesystem>
            <Thin_StoragePool>xxxxxxxxx</Thin_StoragePool>
            <Thick_StoragePool>xxxxxxxx</Thick_StoragePool>
            <WaitInterval>3</WaitInterval>
            <Timeout>60</Timeout>
        </Filesystem>
    </Config>

- `Product` is a type of a storage product. Set it to `V3`.
- `LogicalPortIP` is an IP address of the logical port.
- `Port` is a port name list of bond port or ETH port, used to
  create vlan and logical port. Multi Ports can be configured in
  <Port>(separated by ";"). If <Port> is not configured, then will choose
  an online port on the array.
- `RestURL` is an access address of the REST interface. Multi RestURLs
  can be configured in <RestURL>(separated by ";"). When one of the RestURL
  failed to connect, driver will retry another automatically.
- `UserName` is a user name of an administrator.
- `UserPassword` is a password of an administrator.
- `Thin_StoragePool` is a name of a Thin storage pool to be used.
- `Thick_StoragePool` is a name of a Thick storage pool to be used.
- `WaitInterval` is the interval time of querying the file system status.
- `Timeout` is the timeout period for waiting command execution of a device to
  complete.

Backend Configuration
---------------------

Modify the `manila.conf` Manila configuration file and add share_driver and
manila_huawei_conf_file items.
Example for configuring a storage system:

- `share_driver` = manila.share.drivers.huawei.huawei_nas.HuaweiNasDriver
- `manila_huawei_conf_file` = /etc/manila/manila_huawei_conf.xml
- `driver_handles_share_servers` = True or False

.. note::
    - If `driver_handles_share_servers` is True, the driver will choose a port
      in <Port> to create vlan and logical port for each tenant network.
      And the share type with the DHSS extra spec should be set to True when
      creating shares.
    - If `driver_handles_share_servers` is False, then will use the IP in
      <LogicalPortIP>. Also the share type with the DHSS extra spec should be
      set to False when creating shares.

Restart of manila-share service is needed for the configuration changes to take
effect.

Share Types
-----------

When creating a share, a share type can be specified to determine where and
how the share will be created. If a share type is not specified, the
`default_share_type` set in the Manila configuration file is used.

Manila requires that the share type includes the `driver_handles_share_servers`
extra-spec. This ensures that the share will be created on a backend that
supports the requested driver_handles_share_servers (share networks) capability.
For the Huawei driver, this must be set to False.

Another common Manila extra-spec used to determine where a share is created
is `share_backend_name`. When this extra-spec is defined in the share type,
the share will be created on a backend with a matching share_backend_name.

Manila "share types" may contain qualified extra-specs, -extra-specs that
have significance for the backend driver and the CapabilityFilter. This
commit makes the Huawei driver report the following boolean capabilities:

- capabilities:dedupe
- capabilities:compression
- capabilities:thin_provisioning
- capabilities:huawei_smartcache

  * huawei_smartcache:cachename

- capabilities:huawei_smartpartition

  * huawei_smartpartition:partitionname

The scheduler will choose a host that supports the needed
capability when the CapabilityFilter is used and a share
type uses one or more of the following extra-specs:

- capabilities:dedupe='<is> True' or '<is> False'
- capabilities:compression='<is> True' or '<is> False'
- capabilities:thin_provisioning='<is> True' or '<is> False'
- capabilities:huawei_smartcache='<is> True' or '<is> False'

  * huawei_smartcache:cachename=test_cache_name

- capabilities:huawei_smartpartition='<is> True' or '<is> False'

  * huawei_smartpartition:partitionname=test_partition_name

`thin_provisioning` will be reported as True for backends that use thin
provisioned pool. Backends that use thin provisioning also support Manila's
over-subscription feature. 'thin_provisioning' will be reported as False for
backends that use thick provisioned pool.

`dedupe` will be reported as True for backends that use deduplication
technology.

`compression` will be reported as True for backends that use compression
technology.

`huawei_smartcache` will be reported as True for backends that use smartcache
technology. Adds SSDs into a high-speed cache pool and divides the pool into
multiple cache partitions to cache hotspot data in random and small read I/Os.

`huawei_smartpartition` will be reported as True for backends that use
smartpartition technology. Add share to the smartpartition named
'test_partition_name'. Allocates cache resources based on service characteristics,
ensuring the quality of critical services.

.. note::
    `snapshot_support` will be reported as True for backends that support all
    snapshot functionalities, including create_snapshot, delete_snapshot, and
    create_share_from_snapshot. Huawei Driver does not support
    create_share_from_snapshot API now, so make sure that used `share type` has
    extra spec `snapshot_support` set to `False`.

Restrictions
------------

The Huawei driver has the following restrictions:

- IP and USER access types are supported for NFS.

- Only LDAP domain is supported for NFS.

- Only USER access type is supported for CIFS.

- Only AD domain is supported for CIFS.

The :mod:`manila.share.drivers.huawei.huawei_nas` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.huawei.huawei_nas
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
