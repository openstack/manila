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
  * Only IP access type is supported for NFS.
  * Only USER access type is supported for CIFS.
- Deny CIFS/NFS Share access
- Create snapshot
- Delete snapshot

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
            <RestURL>https://x.x.x.x:8088/deviceManager/rest/</RestURL>
            <UserName>xxxxxxxxx</UserName>
            <UserPassword>xxxxxxxxx</UserPassword>
        </Storage>
        <Filesystem>
            <AllocType>Thin</AllocType>
            <StoragePool>xxxxxxxxx</StoragePool>
            <WaitInterval>3</WaitInterval>
            <Timeout>60</Timeout>
        </Filesystem>
    </Config>

- `Product` is a type of a storage product. Set it to `V3`.
- `LogicalPortIP` is a IP address of the logical port.
- `RestURL` is a access address of the REST interface.
- `UserName` is a user name of an administrator.
- `UserPassword` is a password of an administrator.
- `AllocType` is a type of file system space allocation. Valid values are
  Thick or Thin.
- `StoragePool` is a name of a storage pool to be used.
- `WaitInterval` is the interval time of querying the file system status.
- `Timeout` is the timeout period for wating command execution of a device to
  complete.

Backend Configuration
---------------------

1. Modify the `manila.conf` Manila configuration file and add share_driver and
manila_huawei_conf_file items.
Example for configuring a storage system:

    share_driver = manila.share.drivers.huawei.huawei_nas.HuaweiNasDriver
    manila_huawei_conf_file = /etc/manila/manila_huawei_conf.xml

Restrictions
------------

The Huawei driver has the following restrictions:

- Only IP access type is supported for NFS.

- Only USER access type is supported for CIFS.

- Only one StoragePool can be configured in the configuration file.
