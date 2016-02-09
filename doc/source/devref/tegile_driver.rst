..
      Copyright (c) 2016 Tegile Systems Inc.
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

Tegile Driver
=============

The Tegile Manila driver uses Tegile IntelliFlash Arrays to provide shared
filesystems to OpenStack.

The Tegile Driver interfaces with a Tegile Array via the REST API.

Requirements
------------

- Tegile IntelliFlash version 3.5.1
- For using CIFS, Active Directory must be configured in the Tegile Array.

Supported Operations
--------------------

The following operations are supported on a Tegile Array:

* Create CIFS/NFS Share
* Delete CIFS/NFS Share
* Allow CIFS/NFS Share access
   * Only IP access type is supported for NFS
   * USER access type is supported for NFS and CIFS
   * RW and RO access supported
* Deny CIFS/NFS Share access
   * IP access type is supported for NFS
   * USER access type is supported for NFS and CIFS
* Create snapshot
* Delete snapshot
* Extend share
* Shrink share
* Create share from snapshot

Backend Configuration
---------------------

The following parameters need to be configured in the [DEFAULT]
section of */etc/manila/manila.conf*:

+-----------------------------------------------------------------------------------------------------------------------------------+
|  [DEFAULT]                                                                                                                        |
+============================+======================================================================================================+
|          **Option**        |                                          **Description**                                             |
+----------------------------+-----------+------------------------------------------------------------------------------------------+
|   enabled_share_backends   | Name of the section on manila.conf used to specify a backend.                                        |
|                            | E.g. *enabled_share_backends = tegileNAS*                                                            |
+----------------------------+------------------------------------------------------------------------------------------------------+
|   enabled_share_protocols  | Specify a list of protocols to be allowed for share creation. For Tegile driver this can be:         |
|                            | *NFS* or *CIFS* or *NFS, CIFS*.                                                                      |
+----------------------------+------------------------------------------------------------------------------------------------------+

The following parameters need to be configured in the [backend] section of */etc/manila/manila.conf*:

+-------------------------------------------------------------------------------------------------------------------------------------+
|  [tegileNAS]                                                                                                                        |
+===============================+=====================================================================================================+
|          **Option**           |                                          **Description**                                            |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|   share_backend_name          | A name for the backend.                                                                             |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|   share_driver                | Python module path. For Tegile driver this must be:                                                 |
|                               | *manila.share.drivers.tegile.tegile.TegileShareDriver*.                                             |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|   driver_handles_share_servers| DHSS, Driver working mode. For Tegile driver **this must be**:                                      |
|                               | *False*.                                                                                            |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|   tegile_nas_server           | Tegile array IP to connect from the Manila node.                                                    |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|   tegile_nas_login            | This field is used to provide username credential to Tegile array.                                  |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|   tegile_nas_password         | This field is used to provide password credential to Tegile array.                                  |
+-------------------------------+-----------------------------------------------------------------------------------------------------+
|   tegile_default_project      | This field can be used to specify the default project in Tegile array where shares are created.     |
|                               | This field is optional.                                                                             |
+-------------------------------+-----------------------------------------------------------------------------------------------------+

Below is an example of a valid configuration of Tegile driver:

| ``[DEFAULT]``
| ``enabled_share_backends = tegileNAS``
| ``enabled_share_protocols = NFS,CIFS``

| ``[tegileNAS]``
| ``driver_handles_share_servers = False``
| ``share_backend_name = tegileNAS``
| ``share_driver = manila.share.drivers.tegile.tegile.TegileShareDriver``
| ``tegile_nas_server = 10.12.14.16``
| ``tegile_nas_login = admin``
| ``tegile_nas_password = password``
| ``tegile_default_project = financeshares``

Restart of :term:`manila-share` service is needed for the configuration changes
to take effect.

Restrictions
------------

The Tegile driver has the following restrictions:

- IP access type is supported only for NFS.

- Only FLAT network is supported.

The :mod:`manila.share.drivers.tegile.tegile` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.tegile.tegile
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
    :exclude-members: TegileAPIExecutor, debugger
