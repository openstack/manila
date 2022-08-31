..
      Copyright (c) 2022 Macrosan Technologies Co., Ltd.
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

====================================
Macrosan Driver for OpenStack Manila
====================================
The `Macrosan <http://www.macrosan.com>`__ driver
provides NFS and CIFS shared file systems to Openstack.

Requirements
------------

- The following service should be enabled on NAS system:

  * CIFS
  * NFS

Supported Operations
--------------------

The following operations are supported:

- Create CIFS/NFS Share
- Delete CIFS/NFS Share
- Allow CIFS/NFS Share access

  * Only IP access type is supported for NFS (ro/rw).
  * Only USER access type is supported for CIFS (ro/rw).
- Deny CIFS/NFS Share access
- Extend a share.
- Shrink a share.

Backend Configuration
---------------------

The following parameters need to be configured in the [DEFAULT] section of
manila configuration (/etc/manila/manila.conf):

- `enabled_share_backends` - Name of the section on manila.conf used to specify
  a backend i.e. *enabled_share_backends = macrosan*

- `enabled_share_protocols` - Specify a list of protocols to be allowed for
  share creation. The VPSA driver support the following options: *NFS* or
  *CIFS* or *NFS, CIFS*

The following parameters need to be configured in the [backend] section of
manila configuration (/etc/manila/manila.conf):

- `share_backend_name` = <backend name to enable>
- `share_driver` = manila.share.drivers.macrosan.macrosan_nas.MacrosanNasDriver
- `driver_handles_share_servers` = False
- `macrosan_nas_ip` = <IP address for access to the NAS controller>
- `macrosan_nas_port` = <Port number for access to the NAS controller>
- `macrosan_nas_user` = <username for access>
- `macrosan_nas_password` = <password for the user specified in macrosan_nas_user>
- `macrosan_share_pools` = <Poolname of the NAS controller>


Share Types
-----------

When creating a share, a share type can be specified to determine where and
how the share will be created. If a share type is not specified, the
`default_share_type` set in the manila configuration file is used.

Manila requires that the share type includes the
`driver_handles_share_servers` extra-spec. This ensures that the share
will be created on a backend that supports the requested
driver_handles_share_servers (share networks) capability.
For the Macrosan driver, this must be set to False.


Back-end configuration example
------------------------------

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = macrosan
   enabled_share_protocols = NFS, CIFS

   [macrosan]
   share_backend_name = MACROSAN
   share_driver = manila.share.drivers.macrosan.macrosan_nas.MacrosanNasDriver
   driver_handles_share_servers = False
   macrosan_nas_ip = FAKE_IP
   macrosan_nas_port = 8443
   macrosan_nas_user = FAKE_USER
   macrosan_nas_password = FAKE_PASSWORD
   macrosan_share_pools = fake_pool1, fake_pool2
