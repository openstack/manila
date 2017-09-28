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

Isilon Driver
=============

The EMC manila driver framework (EMCShareDriver) utilizes EMC storage products
to provide shared filesystems to OpenStack. The EMC manila driver is a plugin
based driver which is designed to use different plugins to manage different EMC
storage products.

The Isilon manila driver is a plugin for the EMC manila driver framework which
allows manila to interface with an Isilon backend to provide a shared
filesystem. The EMC driver framework with the Isilon plugin is referred to as
the "Isilon Driver" in this document.

This Isilon Driver interfaces with an Isilon cluster via the REST Isilon
Platform API (PAPI) and the RESTful Access to Namespace API (RAN).

Requirements
------------

- Isilon cluster running OneFS 7.2 or higher

Supported Operations
--------------------

The following operations are supported on an Isilon cluster:

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

Backend Configuration
---------------------

The following parameters need to be configured in the manila configuration file
for the Isilon driver:

* share_driver = manila.share.drivers.dell_emc.driver.EMCShareDriver
* driver_handles_share_servers = False
* emc_share_backend = isilon
* emc_nas_server = <IP address of Isilon cluster>
* emc_nas_server_port = <port to use for Isilon cluster (optional)>
* emc_nas_login = <username>
* emc_nas_password = <password>
* emc_nas_root_dir = <root directory path to create shares (e.g./ifs/manila)>

Restart of :term:`manila-share` service is needed for the configuration changes to take
effect.

Restrictions
------------

The Isilon driver has the following restrictions:

- Only IP access type is supported for NFS and CIFS.

- Only FLAT network is supported.

The :mod:`manila.share.drivers.dell_emc.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.dell_emc.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`manila.share.drivers.dell_emc.plugins.isilon.isilon` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.dell_emc.plugins.isilon.isilon
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
