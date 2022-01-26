.. _shared_file_systems_share_networks:

==============
Share networks
==============

Share networks are essential to allow end users a path to hard multi-tenancy.
When backed by isolated networks, the Shared File Systems service can
guarantee hard network path isolation for the users' shares. Users can be
allowed to designate their project networks as share networks. When a share
network is provided during share creation, the share driver sets up a virtual
share server (NAS server) on the share network and exports shares using this
NAS server. The share server itself is abstracted away from the user. You must
ensure that the storage system can connect the share servers it provisions to
the networks users can use as their share networks.

.. note::

   Not all shared file systems storage backends support share networks.
   Share networks can only be used when using a share type that has the
   specification ``driver_handles_share_servers=True``. To see what storage
   back ends support this specification, refer to the
   :doc:`share_back_ends_feature_support_mapping`.

How to create share network
~~~~~~~~~~~~~~~~~~~~~~~~~~~

To list networks in a project, run:

.. code-block:: console

   $ openstack network list
   +--------------+---------+--------------------+
   | ID           | Name    | Subnets            |
   +--------------+---------+--------------------+
   | bee7411d-... | public  | 884a6564-0f11-...  |
   |              |         | e6da81fa-5d5f-...  |
   | 5ed5a854-... | private | 74dcfb5a-b4d7-...  |
   |              |         | cc297be2-5213-...  |
   +--------------+---------+--------------------+

A share network stores network information that share servers can use where
shares are hosted. You can associate a share with a single share network.
You must always specify a share network when creating a share with a share
type that requests hard multi-tenancy, i.e., has extra-spec
'driver_handles_share_servers=True'.

For more information about supported plug-ins for share networks, see
:ref:`shared_file_systems_network_plugins`.

A share network has these attributes:

- The IP block in Classless Inter-Domain Routing (CIDR) notation from which to
  allocate the network.

- The IP version of the network.

- The network type, which is `vlan`, `vxlan`, `gre`, or `flat`.

If the network uses segmentation, a segmentation identifier. For example, VLAN,
VXLAN, and GRE networks use segmentation.

To create a share network with private network and subnetwork, run:

.. code-block:: console

   $ manila share-network-create --neutron-net-id 5ed5a854-21dc-4ed3-870a-117b7064eb21 \
   --neutron-subnet-id 74dcfb5a-b4d7-4855-86f5-a669729428dc --name my_share_net \
   --description "My first share network" --availability-zone manila-zone-0
   +-------------------+--------------------------------------+
   | Property          | Value                                |
   +-------------------+--------------------------------------+
   | name              | my_share_net                         |
   | segmentation_id   | None                                 |
   | created_at        | 2015-09-24T12:06:32.602174           |
   | neutron_subnet_id | 74dcfb5a-b4d7-4855-86f5-a669729428dc |
   | updated_at        | None                                 |
   | network_type      | None                                 |
   | neutron_net_id    | 5ed5a854-21dc-4ed3-870a-117b7064eb21 |
   | ip_version        | None                                 |
   | cidr              | None                                 |
   | project_id        | 20787a7ba11946adad976463b57d8a2f     |
   | id                | 5c3cbabb-f4da-465f-bc7f-fadbe047b85a |
   | description       | My first share network               |
   +-------------------+--------------------------------------+

The ``segmentation_id``, ``cidr``, ``ip_version``, and ``network_type``
share network attributes are automatically set to the values determined by the
network provider.

.. note::
   You are able to specify the parameter ``availability_zone`` only with API
   versions >= 2.51. From the version 2.51, a share network is able to span
   multiple subnets in different availability zones. The network parameters
   ``neutron_net_id``, ``neutron_subnet_id``, ``segmentation_id``, ``cidr``,
   ``ip_version``, ``network_type``, ``gateway`` and ``mtu`` were moved to the
   share network subnet and no longer pertain to the share network. If you do
   not specify an availability zone during the share network creation, the
   created subnet will be considered default by the Shared File Systems
   Service. A default subnet is expected to be reachable from all availability
   zones in the cloud.

.. note::
   Since API version 2.63, the share network will have two additional fields:
   ``status`` and ``security_service_update_support``. The former indicates the
   current status of a share network, and the latter informs if all the share
   network's resources can hold updating or adding security services after they
   are already deployed.

To check the network list, run:

.. code-block:: console

   $ manila share-network-list
   +--------------------------------------+--------------+
   | id                                   | name         |
   +--------------------------------------+--------------+
   | 5c3cbabb-f4da-465f-bc7f-fadbe047b85a | my_share_net |
   +--------------------------------------+--------------+

If you configured the generic driver with ``driver_handles_share_servers =
True`` (with the share servers) and already had previous operations in the Shared
File Systems service, you can see ``manila_service_network`` in the neutron
list of networks. This network was created by the generic driver for internal
use.

.. code-block:: console

   $ openstack network list
   +--------------+------------------------+--------------------+
   | ID           | Name                   | Subnets            |
   +--------------+------------------------+--------------------+
   | 3b5a629a-e...| manila_service_network | 4f366100-50...     |
   | bee7411d-... | public                 | 884a6564-0f11-...  |
   |              |                        | e6da81fa-5d5f-...  |
   | 5ed5a854-... | private                | 74dcfb5a-b4d7-...  |
   |              |                        | cc297be2-5213-...  |
   +--------------+------------------------+--------------------+

You also can see detailed information about the share network including
``network_type``, and ``segmentation_id`` fields:

.. code-block:: console

   $ openstack network show manila_service_network
   +---------------------------+--------------------------------------+
   | Field                     | Value                                |
   +---------------------------+--------------------------------------+
   | admin_state_up            | UP                                   |
   | availability_zone_hints   |                                      |
   | availability_zones        | nova                                 |
   | created_at                | 2016-12-13T09:31:30Z                 |
   | description               |                                      |
   | id                        | 3b5a629a-e7a1-46a3-afb2-ab666fb884bc |
   | ipv4_address_scope        | None                                 |
   | ipv6_address_scope        | None                                 |
   | mtu                       | 1450                                 |
   | name                      | manila_service_network               |
   | port_security_enabled     | True                                 |
   | project_id                | f6ac448a469b45e888050cf837b6e628     |
   | provider:network_type     | vxlan                                |
   | provider:physical_network | None                                 |
   | provider:segmentation_id  | 73                                   |
   | revision_number           | 7                                    |
   | router:external           | Internal                             |
   | shared                    | False                                |
   | status                    | ACTIVE                               |
   | subnets                   | 682e3329-60b0-440f-8749-83ef53dd8544 |
   | tags                      | []                                   |
   | updated_at                | 2016-12-13T09:31:36Z                 |
   +---------------------------+--------------------------------------+

You also can add and remove the security services from the share network.
For more detail, see :ref:`shared_file_systems_security_services`.

How to reset the state of a share network (Since API version 2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To reset the state of a given share network, run:

.. code-block:: console

   $ manila share-network-reset-state manila_service_network --state active


==============================================
Share network subnets (Since API version 2.51)
==============================================

Share network subnet is an entity that stores network data from the OpenStack
Networking service. A share network can span multiple share network subnets in
different availability zones.

How to create share network subnet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When you create a share network, a primary share network subnet is
automatically created. The share network subnet stores network information
that share servers can use where shares are hosted. If a share network subnet
is not assigned to a specific availability zone, it is considered to be
available across all availability zones. Such a subnet is referred to as
``default`` subnet. A share network can have only one default subnet. However,
having a default subnet is not necessary. A share can be associated with only
one share network. To list share networks in a project, run:

.. code-block:: console

   $ manila share-network-list
   +--------------------------------------+-----------------------+
   | id                                   | name                  |
   +--------------------------------------+-----------------------+
   | 483a9787-5116-48b2-bd89-473022fad060 | sharenetwork1         |
   | bcb9c650-a501-410d-a418-97f28b8ab61a | sharenetwork2         |
   +--------------------------------------+-----------------------+

You can attach any number of share network subnets into a share network.
However, only one share network subnet is allowed per availability zone in a
given share network. If you try to create another subnet in a share network that
already contains a subnet in a specific availability zone, the operation will
be denied.

To create a share network subnet in a specific share network, run:

.. code-block:: console

   $ manila share-network-subnet-create sharenetwork1 \
        --availability-zone manila-zone-0 \
        --neutron-net-id 5ed5a854-21dc-4ed3-870a-117b7064eb21 \
        --neutron-subnet-id 74dcfb5a-b4d7-4855-86f5-a669729428dc
   +--------------------+--------------------------------------+
   | Property           | Value                                |
   +--------------------+--------------------------------------+
   | id                 | 20f3cd2c-0faa-4b4b-a00a-4f188eb1cf38 |
   | availability_zone  | manila-zone-0                        |
   | share_network_id   | 483a9787-5116-48b2-bd89-473022fad060 |
   | share_network_name | sharenetwork1                        |
   | created_at         | 2019-12-03T00:37:30.000000           |
   | segmentation_id    | None                                 |
   | neutron_subnet_id  | 74dcfb5a-b4d7-4855-86f5-a669729428dc |
   | updated_at         | None                                 |
   | neutron_net_id     | 5ed5a854-21dc-4ed3-870a-117b7064eb21 |
   | ip_version         | None                                 |
   | cidr               | None                                 |
   | network_type       | None                                 |
   | mtu                | None                                 |
   | gateway            | None                                 |
   +--------------------+--------------------------------------+

To list all the share network subnets of a given share network, you need to
show the share network, and then all subnets will be displayed, as shown below:

.. code-block:: console

   $ manila share-network-show sharenetwork1
   +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
   | Property              | Value                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
   +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
   | id                    | 483a9787-5116-48b2-bd89-473022fad060                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
   | name                  | sharenetwork1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
   | project_id            | 58ff89e14f9245d7843b8cf290525b5b                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
   | created_at            | 2019-12-03T00:16:39.000000                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
   | updated_at            | 2019-12-03T00:31:58.000000                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
   | description           | None                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
   | share_network_subnets | [{'id': '20f3cd2c-0faa-4b4b-a00a-4f188eb1cf38', 'availability_zone': 'manila-zone-0', 'created_at': '2019-12-03T00:37:30.000000', 'updated_at': None, 'segmentation_id': None, 'neutron_net_id': '5ed5a854-21dc-4ed3-870a-117b7064eb21', 'neutron_subnet_id': '74dcfb5a-b4d7-4855-86f5-a669729428dc', 'ip_version': None, 'cidr': None, 'network_type': None, 'mtu': None, 'gateway': None}, {'id': '8b532c15-3ac7-4ea1-b1bc-732614a82313', 'availability_zone': None, 'created_at': '2019-12-03T00:16:39.000000', 'updated_at': None, 'segmentation_id': None, 'neutron_net_id': None, 'neutron_subnet_id': None, 'ip_version': None, 'cidr': None, 'network_type': None, 'mtu': None, 'gateway': None}] |
   +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

To show a specific share network subnet, run:

.. code-block:: console

   $ manila share-network-subnet-show sharenetwork1 20f3cd2c-0faa-4b4b-a00a-4f188eb1cf38
   +--------------------+--------------------------------------+
   | Property           | Value                                |
   +--------------------+--------------------------------------+
   | id                 | 20f3cd2c-0faa-4b4b-a00a-4f188eb1cf38 |
   | availability_zone  | manila-zone-0                        |
   | share_network_id   | 483a9787-5116-48b2-bd89-473022fad060 |
   | share_network_name | sharenetwork1                        |
   | created_at         | 2019-12-03T00:37:30.000000           |
   | segmentation_id    | None                                 |
   | neutron_subnet_id  | 74dcfb5a-b4d7-4855-86f5-a669729428dc |
   | updated_at         | None                                 |
   | neutron_net_id     | 5ed5a854-21dc-4ed3-870a-117b7064eb21 |
   | ip_version         | None                                 |
   | cidr               | None                                 |
   | network_type       | None                                 |
   | mtu                | None                                 |
   | gateway            | None                                 |
   +--------------------+--------------------------------------+

To delete a share network subnet, run:

.. code-block:: console

   $ manila share-network-subnet-delete sharenetwork1 20f3cd2c-0faa-4b4b-a00a-4f188eb1cf38

If you want to remove a share network subnet, make sure that no other
resource is using the subnet, otherwise the Shared File Systems
Service will deny the operation.
