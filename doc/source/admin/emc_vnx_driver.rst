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

VNX Driver
==========

EMC manila driver framework (EMCShareDriver) utilizes the EMC storage products
to provide the shared filesystems to OpenStack. The EMC manila driver is a
plugin based driver which is designed to use different plugins to manage
different EMC storage products.

VNX plugin is the plugin which manages the VNX to provide shared filesystems.
EMC driver framework with VNX plugin is referred to as VNX driver in this
document.

This driver performs the operations on VNX by XMLAPI and the File command line.
Each backend manages one Data Mover of VNX. Multiple manila backends need to
be configured to manage multiple Data Movers.

.. note::

   Dell EMC VNX driver has been deprecated and will be removed in a future
   release

Requirements
------------

- VNX OE for File version 7.1 or higher.
- VNX Unified, File only, or Gateway system with single storage backend.
- The following licenses should be activated on VNX for File:
  * CIFS
  * NFS
  * SnapSure (for snapshot)
  * ReplicationV2 (for create share from snapshot)

Supported Operations
--------------------

The following operations will be supported on VNX array:

- Create CIFS/NFS Share
- Delete CIFS/NFS Share
- Allow CIFS/NFS Share access
  * Only IP access type is supported for NFS.
  * Only user access type is supported for CIFS.
- Deny CIFS/NFS Share access
- Create snapshot
- Delete snapshot
- Create share from snapshot

While the generic driver creates shared filesystems based on Cinder volumes
attached to Nova VMs, the VNX driver performs similar operations using the
Data Movers on the array.

Pre-Configurations on VNX
-------------------------

1. Enable Unicode on Data mover

VNX driver requires that the Unicode is enabled on Data Mover.

CAUTION: After enabling Unicode, you cannot disable it. If there are some
filesystems created before Unicode is enabled on the VNX, consult the storage
administrator before enabling Unicode.

To check the Unicode status on Data Mover, use the following VNX File command
on VNX control station:

    server_cifs <mover_name> | head
    where:
    mover_name = <name of the Data Mover>

Check the value of `I18N mode` field. UNICODE mode is shown as `I18N mode =
UNICODE`

To enable the Unicode for Data Mover:

    uc_config -on -mover <mover_name>
    where:
    mover_name = <name of the Data Mover>

Refer to the document `Using International Character Sets on VNX for File`
on [EMC support site](https://support.emc.com) for more information.

2. Enable CIFS service on Data Mover

Ensure the CIFS service is enabled on the Data Mover which is going to be
managed by VNX driver.

To start the CIFS service, use the following command:

    server_setup <mover_name> -Protocol cifs -option start [=<n>]
    where:
    <mover_name> = <name of the Data Mover>
    [=<n>] = <number of threads for CIFS users>

Note: If there is 1 GB of memory on the Data Mover, the default is 96 threads;
however, if there is over 1 GB of memory, the default number of threads is 256.

To check the CIFS service status, use this command:

    server_cifs <mover_name> | head
    where:
    <mover_name> = <name of the Data Mover>

The command output will show the number of CIFS threads started.

3. NTP settings on Data Mover

VNX driver only supports CIFS share creation with share network which has an
Active Directory security-service associated.

Creating CIFS share requires that the time on the Data Mover is in sync with
the Active Directory domain so that the CIFS server can join the domain.
Otherwise, the domain join will fail when creating share with this security
service. There is a limitation that the time of the domains used by
security-services even for different tenants and different share networks
should be in sync. Time difference should be less than 10 minutes.

It is recommended to set the NTP server to the same public NTP server on both
the Data Mover and domains used in security services to ensure the time is in
sync everywhere.

Check the date and time on Data Mover:

   server_date <mover_name>
   where:
   mover_name = <name of the Data Mover>

Set the NTP server for Data Mover:

   server_date <mover_name> timesvc start ntp <host> [<host> ...]
   where:
   mover_name = <name of the Data Mover>
   host = <IP address of the time server host>

Note: The host must be running the NTP protocol. Only 4 host entries are
allowed.

4. Configure User Mapping on the Data Mover

Before creating CIFS share using VNX driver, you must select a method of
mapping Windows SIDs to UIDs and GIDs. EMC recommends using usermapper in
single protocol (CIFS) environment which is enabled on VNX by default.

To check usermapper status, use this command syntax:

    server_usermapper <movername>
    where:
    <movername> = <name of the Data Mover>

If usermapper is not started, the following command can be used to start the
usermapper:

    server_usermapper <movername> -enable
    where:
    <movername> = <name of the Data Mover>

For multiple protocol environment, refer to `Configuring VNX User Mapping` on
[EMC support site](https://support.emc.com) for additional information.

5. Network Connection

In the current release, the share created by VNX driver uses the first network
device (physical port on NIC) of Data Mover to access the network.

Go to Unisphere to check the device list:
Settings -> Network -> Settings for File (Unified system only) -> Device.

Backend Configuration
---------------------

The following parameters need to be configured in `/etc/manila/manila.conf`
for the VNX driver:

    emc_share_backend = vnx
    emc_nas_server = <IP address>
    emc_nas_password = <password>
    emc_nas_login = <user>
    emc_nas_server_container = <Data Mover name>
    emc_nas_pool_name = <pool name>
    emc_interface_ports = <Comma separated ports list>
    share_driver = manila.share.drivers.dell_emc.driver.EMCShareDriver
    driver_handles_share_servers = True

- `emc_share_backend` is the plugin name. Set it to `vnx` for the VNX driver.
- `emc_nas_server` is the control station IP address of the VNX system to be
  managed.
- `emc_nas_password` and `emc_nas_login` fields are used to provide credentials
  to the VNX system. Only local users of VNX File is supported.
- `emc_nas_server_container` field is the name of the Data Mover to serve the
  share service.
- `emc_nas_pool_name` is the pool name user wants to create volume from. The
  pools can be created using Unisphere for VNX.
- `emc_interface_ports` is comma separated list specifying the ports(devices) of
  Data Mover that can be used for share server interface.
  Members of the list can be Unix-style glob expressions (supports Unix shell-style
  wildcards). This list is optional. In the absence of this option, any of the ports
  on the Data Mover can be used.
- `driver_handles_share_servers` must be True, the driver will choose a port
  from port list which configured in emc_interface_ports.

Restart of :term:`manila-share` service is needed for the configuration changes to take
effect.

IPv6 support
------------

IPv6 support for VNX driver is introduced in Queens release. The feature is divided
into two parts:

1. The driver is able to manage share or snapshot in the Neutron IPv6 network.
2. The driver is able to connect VNX management interface using its IPv6 address.

Pre-Configurations for IPv6 support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following parameters need to be configured in `/etc/manila/manila.conf`
for the VNX driver:

    network_plugin_ipv6_enabled = True

- `network_plugin_ipv6_enabled` indicates IPv6 is enabled.

If you want to connect VNX using IPv6 address, you should configure IPv6 address
by `nas_cs` command for VNX and specify the address in `/etc/manila/manila.conf`:

    emc_nas_server = <IPv6 address>

Snapshot support
----------------

In the Mitaka and Newton release of OpenStack, Snapshot support is enabled by default for a newly created share type.
Starting with the Ocata release, the snapshot_support extra spec must be set to True in order to allow snapshots for
a share type. If the 'snapshot_support' extra_spec is omitted or if it is set to False, users would not be able to
create snapshots on shares of this share type. The feature is divided into two parts:

1. The driver is able to create/delete snapshot of share.
2. The driver is able to create share from snapshot.

Pre-Configurations for Snapshot support
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following extra specifications need to be configured with share type.

- snapshot_support = True
- create_share_from_snapshot_support = True

For new share type, these extra specifications can be set directly when creating share type:

.. code-block:: console

    manila type-create --snapshot_support True --create_share_from_snapshot_support True ${share_type_name} True

Or you can update already existing share type with command:

.. code-block:: console

    manila type-key ${share_type_name} set snapshot_support=True
    manila type-key ${share_type_name} set create_share_from_snapshot_support=True

To snapshot a share and create share from the snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Firstly, you need create a share from share type that has extra specifications(snapshot_support=True, create_share_from_snapshot_support=True).
Then snapshot the share with command:

.. code-block:: console

    manila snapshot-create ${source_share_name} --name ${target_snapshot_name} --description " "

After creating the snapshot from previous step, you can create share from that snapshot.
Use command:

.. code-block:: console

    manila create nfs 1 --name ${target_share_name} --metadata source=snapshot --description " " --snapshot-id ${source_snapshot_id}

Restrictions
------------

The VNX driver has the following restrictions:

- Only IP access type is supported for NFS.

- Only user access type is supported for CIFS.

- Only FLAT network and VLAN network are supported.

- VLAN network is supported with limitations. The Neutron subnets in different
  VLANs that are used to create share networks cannot have overlapped address
  spaces. Otherwise, VNX may have a problem to communicate with the hosts in
  the VLANs. To create shares for different VLANs with same subnet address, use
  different Data Movers.

- The 'Active Directory' security service is the only supported security
  service type and it is required to create CIFS shares.

- Only one security service can be configured for each share network.

- Active Directory domain name of the 'active_directory' security service
  should be unique even for different tenants.

- The time on Data Mover and the Active Directory domains used in security
  services should be in sync (time difference should be less than 10 minutes).
  It is recommended to use same NTP server on both the Data Mover and Active
  Directory domains.

- On VNX the snapshot is stored in the SavVols. VNX system allows the space
  used by SavVol to be created and extended until the sum of the space consumed
  by all SavVols on the system exceeds the default 20% of the total space
  available on the system. If the 20% threshold value is reached, an alert will
  be generated on VNX. Continuing to create snapshot will cause the old
  snapshot to be inactivated (and the snapshot data to be abandoned). The limit
  percentage value can be changed manually by storage administrator based on
  the storage needs. Administrator is recommended to configure the notification
  on the SavVol usage. Refer to `Using VNX SnapSure` document on [EMC support
  site](https://support.emc.com) for more information.

- VNX has limitations on the overall numbers of Virtual Data Movers,
  filesystems, shares, checkpoints, and etc. Virtual Data Mover(VDM) is created
  by the VNX driver on the VNX to serve as the manila share server. Similarly,
  filesystem is created, mounted, and exported from the VDM over CIFS or NFS
  protocol to serve as the manila share. The VNX checkpoint serves as the
  manila share snapshot. Refer to the `NAS Support Matrix` document on [EMC
  support site](https://support.emc.com) for the limitations and configure the
  quotas accordingly.

The :mod:`manila.share.drivers.dell_emc.driver` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.dell_emc.driver
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`manila.share.drivers.dell_emc.plugins.vnx.connection` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.dell_emc.plugins.vnx.connection
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
