..
      Copyright (c) 2015 EMC Corporation
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

PowerScale Driver
=================

The EMC manila driver framework (EMCShareDriver) utilizes Dell storage products
to provide shared filesystems to OpenStack. The EMC manila driver is a plugin
based driver which is designed to use different plugins to manage different
Dell storage products.

The PowerScale manila driver is a plugin for the EMC manila driver framework
which allows manila to interface with an PowerScale backend to provide a shared
filesystem. The EMC driver framework with the PowerScale plugin is referred to
as the "PowerScale Driver" in this document.

This PowerScale Driver interfaces with an PowerScale cluster via the REST
PowerScale Platform API (PAPI) and the RESTful Access to Namespace API (RAN).

Requirements
------------

- PowerScale cluster running OneFS 9.10 or higher

Supported Operations
--------------------

The following operations are supported on an PowerScale cluster:

* Create CIFS/NFS Share
* Delete CIFS/NFS Share
* Allow CIFS/NFS Share access
   * Only IP access type is supported for NFS and CIFS
   * Only RW access supported
* Deny CIFS/NFS Share access
* Create snapshot
* Delete snapshot
* Create share from snapshot
* Extend share
* Shrink share
* Manage and Unmanage CIFS/NFS share
* Manage and Unmanage snapshot
* Mount snapshot
* Mount point name
* Ensure shares
* Schedule Dedupe job for a share
* Revert to a snapshot
* QoS support

Default access behavior
-----------------------

The PowerScale driver denies access by default. A share or snapshot that has
no access rules cannot be accessed by any client until an access rule is
added.

* NFS: the driver creates the export with ``127.0.0.1`` as its only client.
  This is the loopback address, so a remote host cannot use it and cannot
  mount the export. When the last access rule is removed, the export is set
  back to this state.
* CIFS: the driver creates the SMB share with the host ACL ``deny:ALL``. When
  the last IP rule and user rule are removed, the host ACL is set back to
  ``deny:ALL``.

.. important::

   After you create a share or snapshot, add an access rule before clients
   try to use it. Until then, all clients are denied.

   Existing shares and snapshots are not modified. They are denied by default
   only if their last access rule is removed.

Backend Configuration
---------------------

The following parameters need to be configured in the manila configuration file
for the PowerScale driver:

* share_driver = manila.share.drivers.dell_emc.driver.EMCShareDriver
* driver_handles_share_servers = False
* emc_share_backend = powerscale
* emc_nas_server = <IP address of PowerScale cluster>
* emc_nas_server_port = <port to use for PowerScale cluster (optional)>
* emc_nas_login = <username>
* emc_nas_password = <password>
* emc_nas_root_dir = <root directory path to create shares (e.g./ifs/manila)>

Restart of :term:`manila-share` service is needed for the configuration changes
to take effect.

Restrictions
------------

The PowerScale driver has the following restrictions:

- Only IP access type is supported for NFS and CIFS.

- Only FLAT network is supported.

The :mod:`manila.share.drivers.dell_emc.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.dell_emc.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`manila.share.drivers.dell_emc.plugins.powerscale.powerscale` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.dell_emc.plugins.powerscale.powerscale
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
