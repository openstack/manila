..
      Copyright (c) 2014 EMC Corporation
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


Unity Driver
============

EMC manila driver framework (EMCShareDriver) utilizes the EMC storage products
to provide the shared filesystems to OpenStack. The EMC manila driver is a
plugin based driver which is designed to use different plugins to manage
different EMC storage products.

Unity plugin is the plugin which manages the Unity Storage System to provide
shared filesystems.  EMC driver framework with Unity plugin is referred to as
Unity driver in this document.

This driver performs the operations on Unity by REST API.  Each backend manages
one Unity Storage System. Multiple manila backends need to be configured to
manage multiple Unity Storage Systems.

Requirements
------------

- Unity OE 4.0.1 or higher.
- StorOps 0.5.7 or higher is installed on Manila node.
- Following licenses are activated on Unity:

  * CIFS/SMB Support
  * Network File System (NFS)
  * Thin Provisioning
  * Fiber Channel (FC)
  * Internet Small Computer System Interface (iSCSI)


Supported Operations
--------------------

In detail, users are allowed to do following operation with EMC Unity
Storage Systems.

* Create/delete a NFS share.
* Create/delete a CIFS share.
* Extend the size of a share.
* Modify the host access privilege of a NFS share.
* Modify the user access privilege of a CIFS share.
* Take/Delete snapshot of a share.
* Create a new share from snapshot.


Supported Network Topologies
----------------------------

* flat
* VLAN


Pre-Configurations
------------------

On Manila Node
~~~~~~~~~~~~~~

StorOps library is required to run Unity driver.
Please install it with the pip command.
You may need root privilege to install python libraries.

::

    pip install storops


On Unity System
~~~~~~~~~~~~~~~

1. Configure System level NTP Server

Configure the NTP server for your Unity at:

.. code-block:: console

    Unisphere -> Settings -> Management -> System Time and NTP

Select "Enable NTP synchronization" and add your NTP server(s).

2. Configure System level DNS Server

Configure the DNS server for your Unity at:

.. code-block:: console

    Unisphere -> Settings -> Management -> DNS Server

Select "Configure DNS server address manually" and add your DNS server(s).


Configurations
--------------

Following configurations need to be configured in `/etc/manila/manila.conf`
for the Unity driver.

.. code-block:: ini

    share_driver = manila.share.drivers.dell_emc.driver.EMCShareDriver
    emc_share_backend = unity
    emc_nas_server = <management IP address of the Unity system>
    emc_nas_login = <user with administrator privilege>
    emc_nas_password = <password>
    emc_nas_server_container = [SPA|SPB]
    emc_nas_pool_names = <Comma separated pool names>
    emc_interface_ports = <Comma separated ports list>

- `emc_share_backend` is the plugin name. Set it to `unity` for the Unity
  driver.
- `emc_nas_server` is the management IP for Unity.
- `emc_nas_server_container` is the SP that will be used as share server.
- `emc_nas_pool_names` is the name of the pools to be used by this backend.
  If no name is specified, all storage pools on the system will be managed.
  Wild card character is supported.
  Examples: pool_1, pool_*, *
- `emc_interface_ports` is the white list of the ports to be used for
  connection. Wild card character is supported.
  Examples: spa_eth1, spa_*, *

Restart of :term:`manila-share` service is needed for the configuration changes to take
effect.

IPv6 support
------------

IPv6 support for Unity driver is introduced in Queens release. The feature is divided
into two parts:

1. The driver is able to manage share or snapshot in the Neutron IPv6 network.
2. The driver is able to connect Unity management interface using its IPv6 address.

Pre-Configurations for IPv6 support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following parameters need to be configured in `/etc/manila/manila.conf`
for the Unity driver:

    network_plugin_ipv6_enabled = True

- `network_plugin_ipv6_enabled` indicates IPv6 is enabled.

If you want to connect Unity using IPv6 address, you should configure IPv6 address
by `/net/if/mgmt` uemcli command, `mgmtInterfaceSettings` RESTful api or the system 
settings of Unity GUI for Unity and specify the address in `/etc/manila/manila.conf`:

    emc_nas_server = <IPv6 address>


Restrictions
------------

The Unity driver has following restrictions.

- EMC Unity does not support the same IP in different VLANs.
- Only IP access type is supported for NFS.
- Only user access type is supported for CIFS.


API Implementations
-------------------

Following driver features are implemented in the plugin.

* create_share: Create a share and export it based on the protocol used
  (NFS or CIFS).
* create_share_from_snapshot: Create a share from a snapshot - clone a
  snapshot.
* delete_share: Delete a share.
* extend_share: Extend the maximum size of a share.
* create_snapshot: Create a snapshot for the specified share.
* delete_snapshot: Delete the snapshot of the share.
* update_access: recover, add or delete user/host access to a share.
* allow_access: Allow access (read write/read only) of a user to a
  CIFS share.  Allow access (read write/read only) of a host to a NFS
  share.
* deny_access: Remove access (read write/read only) of a user from
  a CIFS share.  Remove access (read write/read only) of a host from a
  NFS share.
* ensure_share: Check whether share exists or not.
* update_share_stats: Retrieve share related statistics from Unity.
* get_network_allocations_number: Returns number of network allocations for
  creating VIFs.
* setup_server: Set up and configures share server with given network
  parameters.
* teardown_server: Tear down the share server.


The :mod:`manila.share.drivers.dell_emc.driver` Module
------------------------------------------------------

.. automodule:: manila.share.drivers.dell_emc.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`manila.share.drivers.dell_emc.plugins.unity.connection` Module
------------------------------------------------------------------------

.. automodule:: manila.share.drivers.dell_emc.plugins.unity.connection
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
