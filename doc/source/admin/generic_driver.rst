..
      Copyright 2014 Mirantis Inc.
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

Generic approach for share provisioning
=======================================

The Shared File Systems service can be configured to use Nova VMs and Cinder
volumes. Using this driver, Manila will use SSH to configure the shares on
the service virtual machine instance.

The following options may be specified in the manila.conf configuration file:

.. code-block:: ini

  # User in service instance that will be used for authentication.
  # (string value)
  #service_instance_user = <None>

  # Password for service instance user. (string value)
  #service_instance_password = <None>

  # Path to host's private key. (string value)
  #path_to_private_key = <None>

  # Maximum time in seconds to wait for creating service instance.
  # (integer value)
  #max_time_to_build_instance = 300

  # Block SSH connection to the service instance from other networks
  # than service network. (boolean value)
  #limit_ssh_access = false

Additionally, this driver supports both ``DHSS=False`` and ``DHSS=True``.
Depending on which one you use, you need to specify different configuration
options in your manila.conf configuration file.

- With ``DHSS=False``:

.. code-block:: ini

  # Name or ID of service instance in Nova to use for share exports.
  # Used only when share servers handling is disabled. (string value)
  #service_instance_name_or_id = <None>

  # Can be either name of network that is used by service instance
  # within Nova to get IP address or IP address itself (either IPv4 or
  # IPv6) for managing shares there. Used only when share servers
  # handling is disabled. (host address value)
  #service_net_name_or_ip = <None>

  # Can be either name of network that is used by service instance
  # within Nova to get IP address or IP address itself (either IPv4 or
  # IPv6) for exporting shares. Used only when share servers handling is
  # disabled. (host address value)
  #tenant_net_name_or_ip = <None>

- With ``DHSS=True``:

.. code-block:: ini

  # Name of image in Glance, that will be used for service instance
  # creation. Only used if driver_handles_share_servers=True. (string
  # value)
  #service_image_name = manila-service-image

  # Name of service instance. Only used if
  # driver_handles_share_servers=True. (string value)
  #service_instance_name_template = manila_service_instance_%s

  # Keypair name that will be created and used for service instances.
  # Only used if driver_handles_share_servers=True. (string value)
  #manila_service_keypair_name = manila-service

  # Path to hosts public key. Only used if
  # driver_handles_share_servers=True. (string value)
  #path_to_public_key = ~/.ssh/id_rsa.pub

  # Security group name, that will be used for service instance
  # creation. Only used if driver_handles_share_servers=True. (string
  # value)
  #service_instance_security_group = manila-service

  # ID of flavor, that will be used for service instance creation. Only
  # used if driver_handles_share_servers=True. (string value)
  #service_instance_flavor_id = 100

  # Name of manila service network. Used only with Neutron. Only used if
  # driver_handles_share_servers=True. (string value)
  #service_network_name = manila_service_network

  # CIDR of manila service network. Used only with Neutron and if
  # driver_handles_share_servers=True. (string value)
  #service_network_cidr = 10.254.0.0/16

  # This mask is used for dividing service network into subnets, IP
  # capacity of subnet with this mask directly defines possible amount
  # of created service VMs per tenant's subnet. Used only with Neutron
  # and if driver_handles_share_servers=True. (integer value)
  #service_network_division_mask = 28

  # Module path to the Virtual Interface (VIF) driver class. This option
  # is used only by drivers operating in
  # `driver_handles_share_servers=True` mode that provision OpenStack
  # compute instances as share servers. This option is only supported
  # with Neutron networking. Drivers provided in tree work with Linux
  # Bridge (manila.network.linux.interface.BridgeInterfaceDriver) and
  # OVS (manila.network.linux.interface.OVSInterfaceDriver). If the
  # manila-share service is running on a host that is connected to the
  # administrator network, a no-op driver
  # (manila.network.linux.interface.NoopInterfaceDriver) may be used.
  # (string value)
  #interface_driver = manila.network.linux.interface.OVSInterfaceDriver

  # Attach share server directly to share network. Used only with
  # Neutron and if driver_handles_share_servers=True. (boolean value)
  #connect_share_server_to_tenant_network = false

  # ID of neutron network used to communicate with admin network, to
  # create additional admin export locations on. (string value)
  #admin_network_id = <None>

  # ID of neutron subnet used to communicate with admin network, to
  # create additional admin export locations on. Related to
  # 'admin_network_id'. (string value)
  #admin_subnet_id = <None>

Configuring the right options depends on the network layout of your
setup, see next section for more details.

Network configurations
----------------------

If using ``DHSS=True``, there are two possible network configurations that can
be chosen for share provisioning using this driver:

- Service VM (SVM) has one NIC connected to a network that connects to a public
  router. This is, the service VM will be connected to a static administrative
  network created beforehand by an administrator. This approach is valid in
  'flat' network topologies, where a single Neutron network is defined for
  all projects (no tenant networks).
- Service VM has two NICs, first one connected to service network, second one
  connected directly to user's network. This is, in a tenant-networks-enabled
  Neutron deployment, manila will create a dedicated network for the share.

Depending on the setup, specific configuration options are required in the
manila.conf file.

In particular, if you are using only a static administrative network, you need
the following:

.. code-block:: ini

  driver_handles_share_servers = True
  connect_share_server_to_tenant_network = True
  admin_network_id = <value>
  admin_subnet_id = <value>
  # Module path to the Virtual Interface (VIF) driver class. This option
  # is used only by drivers operating in
  # `driver_handles_share_servers=True` mode that provision OpenStack
  # compute instances as share servers. This option is only supported
  # with Neutron networking. Drivers provided in tree work with Linux
  # Bridge (manila.network.linux.interface.BridgeInterfaceDriver) and
  # OVS (manila.network.linux.interface.OVSInterfaceDriver). If the
  # manila-share service is running on a host that is connected to the
  # administrator network, a no-op driver
  # (manila.network.linux.interface.NoopInterfaceDriver) may be used.
  # (string value)
  interface_driver = manila.network.linux.interface.NoopInterfaceDriver

Requirements for service image
------------------------------

- Linux based distro
- NFS server
- Samba server >=3.2.0, that can be configured by data stored in registry
- SSH server
- Two net interfaces configured to DHCP (see network approaches)
- 'exportfs' and 'net conf' libraries used for share actions
- Following files will be used, so if their paths differ one needs to create at
  least symlinks for them:

  * /etc/exports (permanent file with NFS exports)
  * /var/lib/nfs/etab (temporary file with NFS exports used by 'exportfs')
  * /etc/fstab (permanent file with mounted filesystems)
  * /etc/mtab (temporary file with mounted filesystems used by 'mount')

Supported shared filesystems
----------------------------

- NFS (access by IP)
- CIFS (access by IP)

Known restrictions
------------------

- One of Nova's configurations only allows 26 shares per server. This limit
  comes from the maximum number of virtual PCI interfaces that are used for
  block device attaching. There are 28 virtual PCI interfaces, in this
  configuration, two of them are used for server needs and other 26 are used
  for attaching block devices that are used for shares.

- Juno version works only with Neutron. Each share should be created with
  neutron-net and neutron-subnet IDs provided via share-network entity.

- Juno version handles security group, flavor, image, keypair for Nova VM and
  also creates service networks, but does not use availability zones for
  Nova VMs and volume types for Cinder block devices.

- Juno version does not use security services data provided with share-network.
  These data will be just ignored.

- Liberty version adds a share extend capability. Share access will be briefly
  interrupted during an extend operation.

- Liberty version adds a share shrink capability, but this capability is not
  effective because generic driver shrinks only filesystem size and doesn't
  shrink the size of Cinder volume.

- Modifying network-related configuration options, such as
  ``service_network_cidr`` or ``service_network_division_mask``, after manila
  has already created some shares using those options is not supported.

- One of the limitations that severely affects availability in the cloud is the
  Single Point of Failure (SPOF) issue. The driver uses a Nova VM as its NAS
  (NFS/CIFS) server. If/When the server goes down, there is no way to continue
  serving data. Due to this SPOF, today's open source SVM solutions for
  multi-tenant manila service do not really constitute a viable alternative to
  using proprietary, vendor-supplied storage arrays or appliances that combine
  per-tenant virtualization and solid HA recovery mechanisms. They are useful
  as objects of reference and study but are not acceptable to operators of real
  life clouds whose customers will not tolerate having to wait for manual
  intervention to recover from unpredictable storage data path outages.

- The generic driver assumes the manila-share service is running on a node
  where there is an integration bridge where it can plug in the service VM
  (nova instance in this case). This condition does not hold in a common
  deployment topology where manila-share is run on a controller node and
  networking services are run on a separate dedicated node.

Using Windows instances
~~~~~~~~~~~~~~~~~~~~~~~

While the generic driver only supports Linux instances, you may use the
Windows SMB driver when Windows VMs are preferred.

For more details, please check out the following page:
:ref:`windows_smb_driver`.

The :mod:`manila.share.drivers.generic` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.generic
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:

The :mod:`manila.share.drivers.service_instance` Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. automodule:: manila.share.drivers.service_instance
    :noindex:
    :members:
    :undoc-members:
    :show-inheritance:
