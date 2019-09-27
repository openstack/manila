..
      Copyright (c) 2019 Infortrend Technologies Co., Ltd.
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

Infortrend Driver for OpenStack Manila
======================================

The `Infortrend <http://www.infortrend.com/global>`__ Manila driver
provides NFS and CIFS shared file systems to Openstack.

Requirements
------------

- The EonStor GS/GSe series Fireware version 139A23

Supported shared filesystems and operations
-------------------------------------------

This driver supports NFS and CIFS shares.

The following operations are supported:

- Create CIFS/NFS Share
- Delete CIFS/NFS Share
- Allow CIFS/NFS Share access

  * Only IP access type is supported for NFS (ro/rw).
  * Only USER access type is supported for CIFS (ro/rw).
- Deny CIFS/NFS Share access
- Manage a share.
- Unmanage a share.
- Extend a share.
- Shrink a share.

Backend Configuration
---------------------

The following parameters need to be configured in the manila configuration
file for the Infortrend driver:

- `share_backend_name` = <backend name to enable>
- `share_driver` = manila.share.drivers.infortrend.driver.InfortrendNASDriver
- `driver_handles_share_servers` = False
- `infortrend_nas_ip` = <IP address for SSH access to the SAN controller>
- `infortrend_nas_user` = <username with the 'edit' role>
- `infortrend_nas_password` = <password for the user specified in infortrend_nas_user>
- `infortrend_share_pools` = <Poolname of the SAN controller>
- `infortrend_share_channels` = <Data channel for file service in SAN controller>


Share Types
-----------

When creating a share, a share type can be specified to determine where and
how the share will be created. If a share type is not specified, the
`default_share_type` set in the manila configuration file is used.

Manila requires that the share type includes the
`driver_handles_share_servers` extra-spec. This ensures that the share
will be created on a backend that supports the requested
driver_handles_share_servers (share networks) capability.
For the Infortrend driver, this must be set to False.


Back-end configuration example
------------------------------

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = ift-manila
   enabled_share_protocols = NFS, CIFS

   [ift-manila]
   share_backend_name = ift-manila
   share_driver = manila.share.drivers.infortrend.driver.InfortrendNASDriver
   driver_handles_share_servers = False
   infortrend_nas_ip = FAKE_IP
   infortrend_nas_user = FAKE_USER
   infortrend_nas_password = FAKE_PASS
   infortrend_share_pools = pool-1, pool-2
   infortrend_share_channels = 0, 1
