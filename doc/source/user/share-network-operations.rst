.. _share_network:

================================
Create and manage share networks
================================

.. contents:: :local:

A share network stores network information to create and manage shares. A share
network provides a way to designate a network to export shares upon. In the
most common use case, you can create a share network with a private OpenStack
(neutron) network that you own. If the share network is an isolated network,
manila can provide hard guarantees of network and data isolation for your
shared file systems in a multi-tenant cloud. In some clouds, however, shares
cannot be exported directly upon private project networks; and the cloud may
have provider networks that are designated for use with share networks.

In either case, as long as the underlying network is connected to the clients
(virtual machines, containers or bare metals), there will exist a direct path
to communicate with shares exported on the share networks.

.. important::

   In order to use share networks, the share type you choose must have the
   extra specification ``driver_handles_share_servers`` set to True.

Create share networks
~~~~~~~~~~~~~~~~~~~~~

#. Create a share network.

   .. code-block:: console

      $ openstack share network create \
         --name sharenetwork1 \
         --description "Share Network created for demo purposes" \
         --neutron-net-id 5edf25ef-73eb-4635-8be0-8246e7d7417b \
         --neutron-subnet-id 046cd84a-8938-4240-9ebd-ad5d8be10f20
      +-----------------------------------+----------------------------------------------------------+
      | Field                             | Value                                                    |
      +-----------------------------------+----------------------------------------------------------+
      | id                                | 6ee20092-3450-4e53-a70a-cf773e435ca3                     |
      | name                              | sharenetwork1                                            |
      | project_id                        | 58951a7d00fd46f9a98bd038ed5d9e09                         |
      | created_at                        | 2026-04-04T06:46:27.092757                               |
      | updated_at                        | None                                                     |
      | description                       | Share Network created for demo purposes                  |
      | status                            | active                                                   |
      | security_service_update_support   | True                                                     |
      | network_allocation_update_support | True                                                     |
      | share_network_subnets             |                                                          |
      |                                   | id = eafd1ec5-704c-4f6f-b7aa-5626dceda520                |
      |                                   | availability_zone = None                                 |
      |                                   | created_at = 2026-04-04T06:46:27.123626                  |
      |                                   | updated_at = None                                        |
      |                                   | segmentation_id = None                                   |
      |                                   | neutron_net_id = 5edf25ef-73eb-4635-8be0-8246e7d7417b    |
      |                                   | neutron_subnet_id = 046cd84a-8938-4240-9ebd-ad5d8be10f20 |
      |                                   | ip_version = None                                        |
      |                                   | cidr = None                                              |
      |                                   | network_type = None                                      |
      |                                   | mtu = None                                               |
      |                                   | gateway = None                                           |
      |                                   | metadata = {}                                            |
      +-----------------------------------+----------------------------------------------------------+

   .. note::
      When creating a share network, a default share network subnet is
      automatically created. If you do not specify an availability zone, the
      created subnet will be considered default by the Shared File Systems
      service. A default subnet is expected to be available in all availability
      zones of the cloud. You can optionally specify an availability zone
      during creation:

   .. code-block:: console

      $ openstack share network create \
         --name sharenetwork1 \
         --description "Share Network created for demo purposes" \
         --availability-zone manila-zone-0

#. Show the created share network.

   .. code-block:: console

      $ openstack share network show sharenetwork1
      +-----------------------------------+----------------------------------------------------------+
      | Field                             | Value                                                    |
      +-----------------------------------+----------------------------------------------------------+
      | id                                | 6ee20092-3450-4e53-a70a-cf773e435ca3                     |
      | name                              | sharenetwork1                                            |
      | project_id                        | 58951a7d00fd46f9a98bd038ed5d9e09                         |
      | created_at                        | 2026-04-04T06:46:27.092757                               |
      | updated_at                        | None                                                     |
      | description                       | Share Network created for demo purposes                  |
      | status                            | active                                                   |
      | security_service_update_support   | True                                                     |
      | network_allocation_update_support | True                                                     |
      | share_network_subnets             |                                                          |
      |                                   | id = eafd1ec5-704c-4f6f-b7aa-5626dceda520                |
      |                                   | availability_zone = None                                 |
      |                                   | created_at = 2026-04-04T06:46:27.123626                  |
      |                                   | updated_at = None                                        |
      |                                   | segmentation_id = None                                   |
      |                                   | neutron_net_id = 5edf25ef-73eb-4635-8be0-8246e7d7417b    |
      |                                   | neutron_subnet_id = 046cd84a-8938-4240-9ebd-ad5d8be10f20 |
      |                                   | ip_version = None                                        |
      |                                   | cidr = None                                              |
      |                                   | network_type = None                                      |
      |                                   | mtu = None                                               |
      |                                   | gateway = None                                           |
      |                                   | properties =                                             |
      | security_services                 |                                                          |
      +-----------------------------------+----------------------------------------------------------+

List share networks
~~~~~~~~~~~~~~~~~~~

#. List share networks.

   .. code-block:: console

      $ openstack share network list
      +--------------------------------------+---------------+
      | ID                                   | Name          |
      +--------------------------------------+---------------+
      | 6ee20092-3450-4e53-a70a-cf773e435ca3 | sharenetwork1 |
      +--------------------------------------+---------------+

Update share networks
~~~~~~~~~~~~~~~~~~~~~

#. Update the share network data.

   .. code-block:: console

      $ openstack share network set sharenetwork1 \
         --neutron-net-id dfe1ca2e-3191-498e-977b-ac7a90bc9589 \
         --neutron-subnet-id 688616b3-ca88-41c5-bde5-b3633b99f6c4

#. Show details of the updated share network.

   .. code-block:: console

      $ openstack share network show sharenetwork1
      +-----------------------------------+----------------------------------------------------------+
      | Field                             | Value                                                    |
      +-----------------------------------+----------------------------------------------------------+
      | id                                | 6ee20092-3450-4e53-a70a-cf773e435ca3                     |
      | name                              | sharenetwork1                                            |
      | project_id                        | 58951a7d00fd46f9a98bd038ed5d9e09                         |
      | created_at                        | 2026-04-04T06:46:27.092757                               |
      | updated_at                        | 2026-04-04T06:46:47.190630                               |
      | description                       | Updated description                                      |
      | status                            | active                                                   |
      | security_service_update_support   | True                                                     |
      | network_allocation_update_support | True                                                     |
      | share_network_subnets             |                                                          |
      |                                   | id = eafd1ec5-704c-4f6f-b7aa-5626dceda520                |
      |                                   | availability_zone = None                                 |
      |                                   | created_at = 2026-04-04T06:46:27.123626                  |
      |                                   | updated_at = 2026-04-04T06:46:58.895341                  |
      |                                   | segmentation_id = None                                   |
      |                                   | neutron_net_id = dfe1ca2e-3191-498e-977b-ac7a90bc9589    |
      |                                   | neutron_subnet_id = 688616b3-ca88-41c5-bde5-b3633b99f6c4 |
      |                                   | ip_version = None                                        |
      |                                   | cidr = None                                              |
      |                                   | network_type = None                                      |
      |                                   | mtu = None                                               |
      |                                   | gateway = None                                           |
      |                                   | properties =                                             |
      | security_services                 |                                                          |
      +-----------------------------------+----------------------------------------------------------+

   .. note::
      You cannot update the ``neutron_net_id`` and ``neutron_subnet_id`` of
      a share network that has shares exported onto it.

   .. note::
      Updating the ``neutron_net_id`` and ``neutron_subnet_id`` is possible
      only for a default subnet. Non default subnets cannot be updated after
      they are created. You may delete the subnet in question, and re-create
      it.

Add security service/s
~~~~~~~~~~~~~~~~~~~~~~

#. Add a pre existent security service in a given share network.

   .. code-block:: console

      $ openstack share network set sharenetwork1 \
          --new-security-service my_sec_service
      $ openstack share security service list --share-network sharenetwork1
      +--------------------------------------+----------------+--------+------+
      | ID                                   | Name           | Status | Type |
      +--------------------------------------+----------------+--------+------+
      | cf36c739-7d59-4321-90f8-ad3d33b4379d | my_sec_service | new    | ldap |
      +--------------------------------------+----------------+--------+------+

.. note::
   Since API version 2.63, manila supports adding security services to share
   networks that already are in use, depending on the share network's
   support. The share network entity now contains a field called
   ``security_service_update_support`` which holds information whether all
   resources built within it can hold such operation.
   Before starting the operation to actually add the security service to a
   share network that is being used, a check operation must be triggered. See
   :ref:`subsection <share_network_security_service_add_check>`.

List share network security services
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. List all the security services existent in a share network.

   .. code-block:: console

      $ openstack share security service list --share-network sharenetwork1
      +--------------------------------------+----------------+--------+------+
      | ID                                   | Name           | Status | Type |
      +--------------------------------------+----------------+--------+------+
      | cf36c739-7d59-4321-90f8-ad3d33b4379d | my_sec_service | new    | ldap |
      +--------------------------------------+----------------+--------+------+

Remove a security service from a share network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Remove a security service from a given share network.

   .. code-block:: console

      $ openstack share network unset sharenetwork1 \
         --security-service my_sec_service

Delete share networks
~~~~~~~~~~~~~~~~~~~~~

#. Delete a share network.

   .. code-block:: console

      $ openstack share network delete sharenetwork1

.. _share_network_security_service_update_check:

Update share network security service check (Since API version 2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Check if the update for security services of the same type can be performed:

   .. code-block:: console

      $ openstack share network set sharenetwork1 \
         --current-security-service my_sec_service \
         --new-security-service my_sec_service_updated \
         --check-only

      Security service my_sec_service can be replaced with security service my_sec_service_updated on share network sharenetwork1.

Now, the request to update a share network security service should be accepted.

Update share network security services (Since API version 2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Replaces one security service for another of the same type.

   .. code-block:: console

      $ openstack share network set sharenetwork1 \
          --current-security-service my_sec_service \
          --new-security-service my_sec_service_updated
      $ openstack share security service list --share-network sharenetwork1
      +--------------------------------------+------------------------+--------+------+
      | ID                                   | Name                   | Status | Type |
      +--------------------------------------+------------------------+--------+------+
      | b940b445-f727-42b3-bc08-d509cd17c7c9 | my_sec_service_updated | new    | ldap |
      +--------------------------------------+------------------------+--------+------+

.. note::
   The share network entity now contains a field called
   ``security_service_update_support`` which holds information whether all
   resources built within it can hold such operation.
   In order to update security services in share networks that currently
   contain shares, an operation to check if the operation can be completed
   must be performed. See
   :ref:`subsection <share_network_security_service_update_check>`.

.. _share_network_security_service_add_check:

Add share network security service check (Since API version 2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Check if it is possible to add a security service to a share network:

   .. code-block:: console

      $ openstack share network set sharenetwork1 \
         --new-security-service my_sec_service \
         --check-only

      Security service my_sec_service can be added to share network sharenetwork1.
