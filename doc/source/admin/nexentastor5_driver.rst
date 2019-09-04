..
      Copyright 2019 Nexenta by DDN, Inc. All rights reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

NexentaStor5 Driver for OpenStack Manila
========================================

The `NexentaStor5 <http://www.nexenta.com>`__ Manila driver
provides NFS shared file systems to OpenStack.

Requirements
------------

- The NexentaStor 5.1 or newer

Supported shared filesystems and operations
-------------------------------------------

This driver supports NFS shares.

The following operations are supported:

- Create NFS Share
- Delete NFS Share
- Allow NFS Share access

  * Only IP access type is supported for NFS (ro/rw).
- Deny NFS Share access
- Manage a share.
- Unmanage a share.
- Extend a share.
- Shrink a share.
- Create snapshot
- Revert to snapshot
- Delete snapshot
- Create share from snapshot

Backend Configuration
---------------------

The following parameters need to be configured in the manila configuration
file for the NexentaStor5 driver:

- `share_backend_name` = <backend name to enable>
- `share_driver` = manila.share.drivers.nexenta.ns5.nexenta_nas.NexentaNasDriver
- `driver_handles_share_servers` = False
- `nexenta_nas_host` = <Data address to NAS shares>
- `nexenta_user` = <username for management operations>
- `nexenta_password` = <password for management operations>
- `nexenta_pool` = <Pool name where NAS shares are created>
- `nexenta_rest_addresses` = <Management address for Rest API access>
- `nexenta_folder` = <Parent filesystem where all Manila shares are kept>
- `nexenta_nfs` = True

Share Types
-----------

When creating a share, a share type can be specified to determine where and
how the share will be created. If a share type is not specified, the
`default_share_type` set in the manila configuration file is used.

Manila requires that the share type includes the
`driver_handles_share_servers` extra-spec. This ensures that the share
will be created on a backend that supports the requested
driver_handles_share_servers (share networks) capability.
For the NexentaStor driver, this extra-spec's value must be set to False.

Restrictions
------------
- Only IP share access control is allowed for NFS shares.


Back-end configuration example
------------------------------

.. code-block:: ini

   [DEFAULT]
   enabled_share_backends = NexentaStor5

   [NexentaStor5]
   share_backend_name = NexentaStor5
   driver_handles_share_servers = False
   nexenta_folder = manila
   share_driver = manila.share.drivers.nexenta.ns5.nexenta_nas.NexentaNasDriver
   nexenta_rest_addresses = 10.3.1.1,10.3.1.2
   nexenta_nas_host = 10.3.1.10
   nexenta_rest_port = 8443
   nexenta_pool = pool1
   nexenta_nfs = True
   nexenta_user = admin
   nexenta_password = secret_password
   nexenta_thin_provisioning = True
