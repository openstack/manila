=====================
Dell EMC Unity driver
=====================

The EMC Shared File Systems service driver framework (EMCShareDriver)
utilizes the EMC storage products to provide the shared file systems to
OpenStack. The EMC driver is a plug-in based driver which is designed to
use different plug-ins to manage different EMC storage products.

The Unity plug-in manages the Unity system to provide shared filesystems.
The EMC driver framework with the Unity plug-in is referred to as the
Unity driver in this document.

This driver performs the operations on Unity through RESTful APIs. Each backend
manages one Storage Processor of Unity. Configure multiple Shared File
Systems service backends to manage multiple Unity systems.

Requirements
------------

- Unity OE 4.1.x or higher.
- StorOps 1.1.0 or higher is installed on Manila node.
- Following licenses are activated on Unity:

  * CIFS/SMB Support
  * Network File System (NFS)
  * Thin Provisioning
  * Fiber Channel (FC)
  * Internet Small Computer System Interface (iSCSI)


Supported shared filesystems and operations
-------------------------------------------

In detail, users are allowed to do following operation with EMC Unity
Storage Systems.

* Create/delete a NFS share.
* Create/delete a CIFS share.
* Extend the size of a share.
* Shrink the size of a share.
* Modify the host access privilege of a NFS share.
* Modify the user access privilege of a CIFS share.
* Create/Delete snapshot of a share.
* Create a new share from snapshot.
* Revert a share to a snapshot.
* Manage/Unmanage a share server.
* Manage/Unmanage a share.
* Manage/Unmanage a snapshot.


Supported Network Topologies
----------------------------

* Flat

  This type is fully supported by Unity share driver, however flat networks are
  restricted due to the limited number of tenant networks that can be created
  from them.

* VLAN

  We recommend this type of network topology in Manila.
  In most use cases, VLAN is used to isolate the different tenants and provide
  an isolated network for each tenant. To support this function, an
  administrator needs to set a slot connected with Unity Ethernet port in
  ``Trunk`` mode or allow multiple VLANs from the slot.

* VXLAN

  Unity native VXLAN is still unavailable. However, with the `HPB
  <http://specs.openstack.org/openstack/neutron-specs/specs/kilo/ml2-hierarchical-port-binding.html>`_
  (Hierarchical Port Binding) in Networking and Shared file system services,
  it is possible that Unity co-exists with VXLAN enabled network environment.

Pre-Configurations
------------------

On Manila Node
~~~~~~~~~~~~~~~

Python library ``storops`` is required to run Unity driver.
Install it with the ``pip`` command.
You may need root privilege to install python libraries.

.. code-block:: console

    $ pip install storops


On Unity System
~~~~~~~~~~~~~~~~

#. Configure system level NTP server.

   Open ``Unisphere`` of your Unity system and navigate to:

   .. code-block:: console

      Unisphere -> Settings -> Management -> System Time and NTP

   Select ``Enable NTP synchronization`` and add your NTP server(s).

   The time on the Unity system and the Active Directory domains
   used in security services should be in sync. We recommend
   using the same NTP server on both the Unity system and Active
   Directory domains.

#. Configure system level DNS server.

   Open ``Unisphere`` of your Unity system and navigate to:

   .. code-block:: console

      Unisphere -> Settings -> Management -> DNS Server

   Select ``Configure DNS server address manually`` and add your DNS server(s).


Backend configurations
----------------------

Following configurations need to be configured in `/etc/manila/manila.conf`
for the Unity driver.

.. code-block:: ini

    share_driver = manila.share.drivers.dell_emc.driver.EMCShareDriver
    emc_share_backend = unity
    emc_nas_server = <management IP address of the Unity system>
    emc_nas_login = <user with administrator privilege>
    emc_nas_password = <password>
    unity_server_meta_pool = <pool name>
    unity_share_data_pools = <comma separated pool names>
    unity_ethernet_ports = <comma separated ports list>
    driver_handles_share_servers = True/False
    unity_share_server = <name of NAS server in Unity system>
    report_default_filter_function = True/False

- `emc_share_backend`
    The plugin name. Set it to `unity` for the Unity driver.

- `emc_nas_server`
    The management IP for Unity.

- `unity_server_meta_pool`
    The name of the pool to persist the meta-data of NAS server.
    This option is required.

- `unity_share_data_pools`
    Comma separated list specifying the name of the pools to be used
    by this backend. Do not set this option if all storage pools
    on the system can be used.
    Wild card character is supported.

    Examples:

    .. code-block:: ini

       # Only use pool_1
       unity_share_data_pools = pool_1
       # Only use pools whose name stars from pool_
       unity_share_data_pools = pool_*
       # Use all pools on Unity
       unity_share_data_pools = *

- `unity_ethernet_ports`
    Comma separated list specifying the ethernet ports of Unity system
    that can be used for share. Do not set this option if all ethernet ports
    can be used.
    Wild card character is supported. Both the normal ethernet port and link
    aggregation port can be used by Unity share driver.


    Examples:

    .. code-block:: ini

       # Only use spa_eth1
       unity_ethernet_ports = spa_eth1
       # Use port whose name stars from spa_
       unity_ethernet_ports = spa_*
       # Use all Link Aggregation ports
       unity_ethernet_ports = sp*_la_*
       # Use all available ports
       unity_ethernet_ports = *

- `driver_handles_share_servers`
    Unity driver requires this option to be as `True` or `False`.
    Need to set `unity_share_server` when the value is `False`.

- `unity_share_server`
    One of NAS server names in Unity, it is used for share creation when
    the driver is in `DHSS=False` mode.

- `report_default_filter_function`
    Whether or not report default filter function. Default value is False.
    However, this value will be changed to True in a future release to ensure
    compliance with design expectations in Manila. So we recommend always
    setting this option in your deployment to True or False per your desired
    behavior.

Restart of :term:`manila-share` service is needed for the configuration
changes to take effect.

Supported MTU size
------------------

Unity currently only supports 1500 and 9000 as the mtu size, the user can
change the above mtu size from Unity Unisphere:

#. In the Unisphere, go to `Settings`, `Access`, and then `Ethernet`.
#. Double click the ethernet port.
#. Select the `MTU` size from the drop down list.

The Unity driver will select the port where mtu is equal to the mtu
of share network during share server creation.

IPv6 support
------------

IPv6 support for Unity driver is introduced in Queens release. The feature
is divided into two parts:

#. The driver is able to manage share or snapshot in the Neutron IPv6 network.
#. The driver is able to connect Unity management interface using its IPv6
   address.

Pre-Configurations for IPv6 support
-----------------------------------

The following parameters need to be configured in `/etc/manila/manila.conf`
for the Unity driver:

    network_plugin_ipv6_enabled = True

- `network_plugin_ipv6_enabled` indicates IPv6 is enabled.

If you want to connect Unity using IPv6 address, you should configure IPv6
address by `/net/if/mgmt` uemcli command, `mgmtInterfaceSettings` RESTful api
or the system settings of Unity GUI for Unity and specify the address in
`/etc/manila/manila.conf`:

    emc_nas_server = <IPv6 address>

Supported share creation in mode that driver does not create and destroy share servers (DHSS=False)
---------------------------------------------------------------------------------------------------

To create a file share in this mode, you need to:

#. Create NAS server with network interface in Unity system.
#. Set 'driver_handles_share_servers=False' and 'unity_share_server' in
   ``/etc/manila/manila.conf``:

    .. code-block:: ini

        driver_handles_share_servers = False
        unity_share_server = <name of NAS server in Unity system>

#. Specify the share type with driver_handles_share_servers = False extra
   specification:

    .. code-block:: console

        $ manila type-create ${share_type_name} False

#. Create share.

    .. code-block:: console

        $ manila create ${share_protocol} ${size} --name ${share_name} --share-type ${share_type_name}

.. note::

    Do not specify the share network in share creation command because
    no share servers will be created.
    Driver will use the unity_share_server specified for share creation.

Snapshot support
----------------

In the Mitaka and Newton release of OpenStack, Snapshot support is enabled by
default for a newly created share type.
Starting with the Ocata release, the snapshot_support extra spec must be set
to True in order to allow snapshots for a share type. If the 'snapshot_support'
extra_spec is omitted or if it is set to False, users would not be able to
create snapshots on shares of this share type. The feature is divided into
two parts:

1. The driver is able to create/delete snapshot of share.
2. The driver is able to create share from snapshot.

Pre-Configurations for Snapshot support
---------------------------------------

The following extra specifications need to be configured with share type.

- snapshot_support = True
- create_share_from_snapshot_support = True

For new share type, these extra specifications can be set directly when
creating share type:

.. code-block:: console

    $ manila type-create --snapshot_support True --create_share_from_snapshot_support True ${share_type_name} True

Or you can update already existing share type with command:

.. code-block:: console

    $ manila type-key ${share_type_name} set snapshot_support=True
    $ manila type-key ${share_type_name} set create_share_from_snapshot_support=True

To snapshot a share and create share from the snapshot
------------------------------------------------------

Firstly, you need create a share from share type that has extra specifications
(snapshot_support=True, create_share_from_snapshot_support=True).
Then snapshot the share with command:

.. code-block:: console

    $ manila snapshot-create ${source_share_name} --name ${target_snapshot_name} --description " "

After creating the snapshot from previous step, you can create share from that
snapshot. Use command:

.. code-block:: console

    $ manila create nfs 1 --name ${target_share_name} --metadata source=snapshot --description " " --snapshot-id ${source_snapshot_id}

To manage an existing share server
----------------------------------

To manage a share server existing in Unity System, you need to:

#. Create network, subnet, port (ip address of nas server in Unity system) and
   share network in OpenStack.

    .. code-block:: console

        $ openstack network create ${network_name} --provider-network-type ${network_type}
        $ openstack subnet create ${subnet_name} --network ${network_name} --subnet-range ${subnet_range}
        $ openstack port create --network ${network_name} --fixed-ip subnet=${subnet_name},ip-address=${ip address} \
          ${port_name} --device-owner=manila:share
        $ manila share-network-create --name ${share_network_name} --neutron-net-id ${network_name} \
          --neutron-subnet-id ${subnet_name}

#. Manage the share server in OpenStack:

    .. code-block:: console

        $ manila share-server-manage ${host} ${share_network_name} ${identifier}

    .. note::

        '${identifier}' is the nas server name in Unity system.

To un-manage a Manila share server
----------------------------------
To unmanage a share server existing in OpenStack:

    .. code-block:: console

        $ manila share-server-unmanage ${share_server_id}

To manage an existing share
---------------------------

To manage a share existing in Unity System:

- In DHSS=True mode

  Need make sure the related share server is existing in OpenStack, otherwise
  need to manage share server first (check the step of 'Supported Manage share
  server').

    .. code-block:: console

        $ manila manage ${service_host} ${protocol} '${export_path}' --name ${share_name} --driver_options size=${share_size} \
          --share_type ${share_type} --share_server_id ${share_server_id}

    .. note::

        '${share_server_id}' is the id of share server in OpenStack.
        '${share_type}' should have the property 'driver_handles_share_servers=True'.

- In DHSS=False mode

    .. code-block:: console

        $ manila manage ${service_host} ${protocol} '${export_path}' --name ${share_name} --driver_options size=${share_size} \
          --share_type ${share_type}

    .. note::

        '${share_type}' should have the property 'driver_handles_share_servers=False'.

To un-manage a Manila share
---------------------------
To unmanage a share existing in OpenStack:

    .. code-block:: console

        $ manila unmanage ${share_id}

To manage an existing share snapshot
------------------------------------
To manage a snapshot existing in Unity System, you need make sure the related
share instance is existing in OpenStack, otherwise need to manage share first
(check the step of 'Supported Manage share').

    .. code-block:: console

        $ manila snapshot-manage --name ${name} ${share_name} ${provider_location} --driver_options size=${snapshot_size}

    .. note::

        '${provider_location}' is the snapshot name in Unity system.
        '${share_name}' is the share name or id in OpenStack.

To un-manage a Manila share snapshot
------------------------------------
To unmanage a snapshot existing in OpenStack:

    .. code-block:: console

        $ manila snapshot-unmanage ${snapshot_id}

Supported security services
---------------------------

Unity share driver provides ``IP`` based authentication method support for
``NFS`` shares and ``user`` based authentication method for ``CIFS`` shares
respectively. For ``CIFS`` share, Microsoft Active Directory is the only
supported security service.

.. _unity_file_io_load_balance:


IO Load balance
---------------

The Unity driver automatically distributes the file interfaces per storage
processor based on the option ``unity_ethernet_ports``. This balances IO
traffic. The recommended configuration for ``unity_ethernet_ports`` specifies
balanced ports per storage processor. For example:

.. code-block:: ini

   # Use eth2 from both SPs
   unity_ethernet_ports = spa_eth2, spb_eth2


Default filter function
-----------------------

Unity does not support the file system creation with size smaller than 3GB, if
the size of share user create is smaller than 3GB, Unity driver will supplement
the size to 3GB in Unity.

Unity driver implemented the get_default_filter_function API to report the
default filter function, if the share size is smaller than 3GB, Manila will
not schedule the share creation to Unity backend.

Unity driver provides an option ``report_default_filter_function`` to disable
or enable the filter function reporting, the default value is disabled.


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
* shrink_share: Shrink the minimum size of a share.
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
* revert_to_snapshot: Revert a share to a snapshot.
* get_default_filter_function: Report a default filter function.


Driver options
--------------

Configuration options specific to this driver:

.. include:: ../../tables/manila-unity.inc
