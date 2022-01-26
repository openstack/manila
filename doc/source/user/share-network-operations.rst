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

      $ manila share-network-create \
         --name sharenetwork1 \
         --description "Share Network created for demo purposes" \
         --neutron-net-id c297b020-025a-4f3e-8120-57ea90404afb \
         --neutron-subnet-id 29ecfbd5-a9be-467e-8b4a-3415d1f82888
      +-------------------+-----------------------------------------+
      | Property          | Value                                   |
      +-------------------+-----------------------------------------+
      | name              | sharenetwork1                           |
      | segmentation_id   | None                                    |
      | created_at        | 2019-07-02T11:14:06.228816              |
      | neutron_subnet_id | 29ecfbd5-a9be-467e-8b4a-3415d1f82888    |
      | updated_at        | None                                    |
      | network_type      | None                                    |
      | neutron_net_id    | c297b020-025a-4f3e-8120-57ea90404afb    |
      | ip_version        | None                                    |
      | cidr              | None                                    |
      | project_id        | 907004508ef4447397ce6741a8f037c1        |
      | id                | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1    |
      | description       | Share Network created for demo purposes |
      +-------------------+-----------------------------------------+

#. Show the created share network.

   .. code-block:: console

      $ manila share-network-show sharenetwork1
      +-------------------+--------------------------------------+
      | Property          | Value                                |
      +-------------------+--------------------------------------+
      | id                | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1 |
      | name              | sharenetwork1                        |
      | project_id        | 5b23075b4b504261a5987b18588f86cf     |
      | created_at        | 2019-10-09T04:19:31.000000           |
      | updated_at        | None                                 |
      | neutron_net_id    | c297b020-025a-4f3e-8120-57ea90404afb |
      | neutron_subnet_id | 29ecfbd5-a9be-467e-8b4a-3415d1f82888 |
      | network_type      | None                                 |
      | segmentation_id   | None                                 |
      | cidr              | None                                 |
      | ip_version        | None                                 |
      | description       | None                                 |
      | gateway           | None                                 |
      | mtu               | None                                 |
      +-------------------+--------------------------------------+

   .. note::
      Since API version 2.51, a share network is able to span multiple
      subnets in different availability zones and the network information
      will be stored on each subnet. To accommodate adding multiple subnets,
      the share network create command was updated to accept an availability
      zone as parameter. This parameter will be used in the share network
      creation process which also creates a new subnet. If you do not specify
      an availability zone, the created subnet will be considered default by
      the Shared File Systems service. A default subnet is expected to be
      available in all availability zones of the cloud. So when you are
      creating a share network, the output will be similar to:

   .. code-block:: console

      $ manila share-network-create \
         --name sharenetwork1 \
         --description "Share Network created for demo purposes" \
         --availability-zone manila-zone-0
      +-----------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | Property              | Value                                                                                                                                                                                                                                                                                                                    |
      +-----------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | id                    | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1                                                                                                                                                                                                                                                                                     |
      | name                  | sharenetwork1                                                                                                                                                                                                                                                                                                            |
      | project_id            | 8c2962a4832743469a336f7c179f7d34                                                                                                                                                                                                                                                                                         |
      | created_at            | 2019-10-09T04:19:31.000000                                                                                                                                                                                                                                                                                               |
      | updated_at            | None                                                                                                                                                                                                                                                                                                                     |
      | description           | Share Network created for demo purposes                                                                                                                                                                                                                                                                                  |
      | share_network_subnets | [{'id': '900d9ddc-7062-404e-8ef5-f63b84782d89', 'availability_zone': 'manila-zone-0', 'created_at': '2019-10-09T04:19:31.000000', 'updated_at': None, 'segmentation_id': None, 'neutron_subnet_id': None, 'neutron_net_id': None, 'ip_version': None, 'cidr': None, 'network_type': None, 'mtu': None, 'gateway': None}] |
      +-----------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

List share networks
~~~~~~~~~~~~~~~~~~~

#. List share networks.

   .. code-block:: console

      $ manila share-network-list
      +--------------------------------------+---------------+
      | id                                   | name          |
      +--------------------------------------+---------------+
      | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1 | sharenetwork1 |
      +--------------------------------------+---------------+

Update share networks
~~~~~~~~~~~~~~~~~~~~~

#. Update the share network data.

   .. code-block:: console

      $ manila share-network-update sharenetwork1 \
         --neutron-net-id a27160ca-5595-4c62-bf54-a04fb7b14316 \
         --neutron-subnet-id f043f4b0-c05e-493f-bbe9-99689e2187d2
         +-------------------+--------------------------------------+
         | Property          | Value                                |
         +-------------------+--------------------------------------+
         | id                | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1 |
         | name              | sharenetwork1                        |
         | project_id        | 5b23075b4b504261a5987b18588f86cf     |
         | created_at        | 2019-10-09T04:19:31.000000           |
         | updated_at        | 2019-10-10T17:14:08.970945           |
         | neutron_net_id    | a27160ca-5595-4c62-bf54-a04fb7b14316 |
         | neutron_subnet_id | f043f4b0-c05e-493f-bbe9-99689e2187d2 |
         | network_type      | None                                 |
         | segmentation_id   | None                                 |
         | cidr              | None                                 |
         | ip_version        | None                                 |
         | description       | None                                 |
         | gateway           | None                                 |
         | mtu               | None                                 |
         +-------------------+--------------------------------------+

#. Show details of the updated share network.

   .. code-block:: console

      $ manila share-network-show sharenetwork1
      +-------------------+--------------------------------------+
      | Property          | Value                                |
      +-------------------+--------------------------------------+
      | id                | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1 |
      | name              | sharenetwork1                        |
      | project_id        | 5b23075b4b504261a5987b18588f86cf     |
      | created_at        | 2019-10-09T04:19:31.000000           |
      | updated_at        | 2019-10-10T17:14:09.000000           |
      | neutron_net_id    | a27160ca-5595-4c62-bf54-a04fb7b14316 |
      | neutron_subnet_id | f043f4b0-c05e-493f-bbe9-99689e2187d2 |
      | network_type      | None                                 |
      | segmentation_id   | None                                 |
      | cidr              | None                                 |
      | ip_version        | None                                 |
      | description       | None                                 |
      | gateway           | None                                 |
      | mtu               | None                                 |
      +-------------------+--------------------------------------+

   .. note::
      You cannot update the ``neutron_net_id`` and ``neutron_subnet_id`` of
      a share network that has shares exported onto it.

   .. note::
      From API version 2.51, updating the ``neutron_net_id`` and
      ``neutron_subnet_id`` is possible only for a default subnet. Non default
      subnets cannot be updated after they are created. You may delete the
      subnet in question, and re-create it. The output will look as shown
      below:

   .. code-block:: console

      $ manila share-network-update sharenetwork1 \
         --neutron-net-id a27160ca-5595-4c62-bf54-a04fb7b14316 \
         --neutron-subnet-id f043f4b0-c05e-493f-bbe9-99689e2187d2
      +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | Property              | Value                                                                                                                                                                                                                                                                                                                                                                                                     |
      +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | id                    | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1                                                                                                                                                                                                                                                                                                                                                                      |
      | name                  | sharenetwork1                                                                                                                                                                                                                                                                                                                                                                                             |
      | project_id            | 8c2962a4832743469a336f7c179f7d34                                                                                                                                                                                                                                                                                                                                                                          |
      | created_at            | 2019-10-09T04:19:31.000000                                                                                                                                                                                                                                                                                                                                                                                |
      | updated_at            | 2019-10-10T17:14:09.000000                                                                                                                                                                                                                                                                                                                                                                                |
      | description           | Share Network created for demo purposes                                                                                                                                                                                                                                                                                                                                                                   |
      | share_network_subnets | [{'id': '900d9ddc-7062-404e-8ef5-f63b84782d89', 'availability_zone': None, 'created_at': '2019-10-09T04:19:31.000000', 'updated_at': '2019-10-09T07:39:59.000000', 'segmentation_id': None, 'neutron_net_id': 'a27160ca-5595-4c62-bf54-a04fb7b14316', 'neutron_subnet_id': 'f043f4b0-c05e-493f-bbe9-99689e2187d2', 'ip_version': None, 'cidr': None, 'network_type': None, 'mtu': None, 'gateway': None}] |
      +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Share network show
~~~~~~~~~~~~~~~~~~

#. Show details of a share network.

   .. code-block:: console

      $ manila share-network-show sharenetwork1
      +-------------------+--------------------------------------+
      | Property          | Value                                |
      +-------------------+--------------------------------------+
      | id                | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1 |
      | name              | sharenetwork1                        |
      | project_id        | 5b23075b4b504261a5987b18588f86cf     |
      | created_at        | 2019-10-09T04:19:31.000000           |
      | updated_at        | 2019-10-10T17:14:09.000000           |
      | neutron_net_id    | fake_updated_net_id                  |
      | neutron_subnet_id | fake_updated_subnet_id               |
      | network_type      | None                                 |
      | segmentation_id   | None                                 |
      | cidr              | None                                 |
      | ip_version        | None                                 |
      | description       | None                                 |
      | gateway           | None                                 |
      | mtu               | None                                 |
      +-------------------+--------------------------------------+

   .. note::
      Since API version 2.51, the ``share-network-show`` command also shows
      a list of subnets contained in the share network as show below.

   .. code-block:: console

      +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | Property              | Value                                                                                                                                                                                                                                                                                                                                                                                                     |
      +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | id                    | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1                                                                                                                                                                                                                                                                                                                                                                      |
      | name                  | sharenetwork1                                                                                                                                                                                                                                                                                                                                                                                             |
      | project_id            | 8c2962a4832743469a336f7c179f7d34                                                                                                                                                                                                                                                                                                                                                                          |
      | created_at            | 2019-10-09T04:19:31.000000                                                                                                                                                                                                                                                                                                                                                                                |
      | updated_at            | None                                                                                                                                                                                                                                                                                                                                                                                                      |
      | description           | Share Network created for demo purposes                                                                                                                                                                                                                                                                                                                                                                   |
      | share_network_subnets | [{'id': '900d9ddc-7062-404e-8ef5-f63b84782d89', 'availability_zone': None, 'created_at': '2019-10-09T04:19:31.000000', 'updated_at': '2019-10-09T07:39:59.000000', 'segmentation_id': None, 'neutron_net_id': 'fake_updated_net_id', 'neutron_subnet_id': 'fake_updated_subnet_id', 'ip_version': None, 'cidr': None, 'network_type': None, 'mtu': None, 'gateway': None}]                                |
      +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

   .. note::
      Since API version 2.63, the ``share-network-show`` command also shows
      the ``status`` and ``security_service_update_support`` fields.

   .. code-block:: console

      +---------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | Property                        | Value                                                                                                                                                                                                                                                                                                                                                                                                     |
      +---------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | id                              | feed6a6c-f9e0-45ba-9a2b-0db76bde63e1                                                                                                                                                                                                                                                                                                                                                                      |
      | name                            | sharenetwork1                                                                                                                                                                                                                                                                                                                                                                                             |
      | project_id                      | 8c2962a4832743469a336f7c179f7d34                                                                                                                                                                                                                                                                                                                                                                          |
      | created_at                      | 2019-10-09T04:19:31.000000                                                                                                                                                                                                                                                                                                                                                                                |
      | updated_at                      | None                                                                                                                                                                                                                                                                                                                                                                                                      |
      | description                     | Share Network created for demo purposes                                                                                                                                                                                                                                                                                                                                                                   |
      | status                          | active                                                                                                                                                                                                                                                                                                                                                                                                    |
      | security_service_update_support | True                                                                                                                                                                                                                                                                                                                                                                                                      |
      | share_network_subnets           | [{'id': '900d9ddc-7062-404e-8ef5-f63b84782d89', 'availability_zone': None, 'created_at': '2019-10-09T04:19:31.000000', 'updated_at': '2019-10-09T07:39:59.000000', 'segmentation_id': None, 'neutron_net_id': 'fake_updated_net_id', 'neutron_subnet_id': 'fake_updated_subnet_id', 'ip_version': None, 'cidr': None, 'network_type': None, 'mtu': None, 'gateway': None}]                                |
      +---------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Add security service/s
~~~~~~~~~~~~~~~~~~~~~~

#. Add a pre existent security service in a given share network.

   .. code-block:: console

      $ manila share-network-security-service-add \
          sharenetwork1 \
          my_sec_service
      $ manila share-network-security-service-list sharenetwork1
      +--------------------------------------+----------------+--------+------+
      | id                                   | name           | status | type |
      +--------------------------------------+----------------+--------+------+
      | 50303c35-2c53-4d37-a0d9-61dfe3789569 | my_sec_service | new    | ldap |
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

      $ manila share-network-security-service-list sharenetwork1
      +--------------------------------------+----------------+--------+------+
      | id                                   | name           | status | type |
      +--------------------------------------+----------------+--------+------+
      | 50303c35-2c53-4d37-a0d9-61dfe3789569 | my_sec_service | new    | ldap |
      +--------------------------------------+----------------+--------+------+

Remove a security service from a share network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Remove a security service from a given share network.

   .. code-block:: console

      $ manila share-network-security-service-remove \
         sharenetwork1 \
         my_sec_service
      $ manila share-network-security-service-list sharenetwork1
      +----+------+--------+------+
      | id | name | status | type |
      +----+------+--------+------+
      +----+------+--------+------+

Delete share networks
~~~~~~~~~~~~~~~~~~~~~

#. Delete a share network.

   .. code-block:: console

      $ manila share-network-delete sharenetwork1

#. List all share networks

   .. code-block:: console

      $ manila share-network-list
      +--------------------------------------+---------------+
      | id                                   | name          |
      +--------------------------------------+---------------+
      +--------------------------------------+---------------+

.. _share_network_security_service_update_check:

Update share network security service check (Since API version 2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Check if the update for security services of the same type can be performed:

   .. code-block:: console

      $ manila share-network-security-service-update-check \
         sharenetwork1 \
         my_sec_service \
         my_sec_service_updated
      +---------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | Property            | Value                                                                                                                                                                      |
      +---------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | compatible          | None                                                                                                                                                                       |
      | requested_operation | {'operation': 'update_security_service', 'current_security_service': 50303c35-2c53-4d37-a0d9-61dfe3789569, 'new_security_service': '8971c5f6-52ec-4c53-bf6a-3fae38a9221e'} |
      +---------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

#. Check the result of the operation:

   .. code-block:: console

      $ manila share-network-security-service-update-check \
         sharenetwork1 \
         my_sec_service \
         my_sec_service_updated
      +---------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | Property            | Value                                                                                                                                                                      |
      +---------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | compatible          | True                                                                                                                                                                       |
      | requested_operation | {'operation': 'update_security_service', 'current_security_service': 50303c35-2c53-4d37-a0d9-61dfe3789569, 'new_security_service': '8971c5f6-52ec-4c53-bf6a-3fae38a9221e'} |
      +---------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

Now, the request to update a share network security service should be accepted.

Update share network security services (Since API version 2.63)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Replaces one security service for another of the same type.

   .. code-block:: console

      $ manila share-network-security-service-update \
          sharenetwork1 \
          my_sec_service \
          my_sec_service_updated
      $ manila share-network-security-service-list sharenetwork1
      +--------------------------------------+------------------------+--------+------+
      | id                                   | name                   | status | type |
      +--------------------------------------+------------------------+--------+------+
      | 8971c5f6-52ec-4c53-bf6a-3fae38a9221e | my_sec_service_updated | new    | ldap |
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

      $ manila share-network-security-service-add-check \
         sharenetwork1 \
         my_sec_service
      +---------------------+-----------------------------------------------------------------------------------------------------------------------------------------+
      | Property            | Value                                                                                                                                   |
      +---------------------+-----------------------------------------------------------------------------------------------------------------------------------------+
      | compatible          | None                                                                                                                                    |
      | requested_operation | {'operation': 'add_security_service', 'current_security_service': None, 'new_security_service': '50303c35-2c53-4d37-a0d9-61dfe3789569'} |
      +---------------------+-----------------------------------------------------------------------------------------------------------------------------------------+

#. Check if the result of the operation:

   .. code-block:: console

      $ manila share-network-security-service-add-check \
         sharenetwork1 \
         my_sec_service
      +---------------------+-----------------------------------------------------------------------------------------------------------------------------------------+
      | Property            | Value                                                                                                                                   |
      +---------------------+-----------------------------------------------------------------------------------------------------------------------------------------+
      | compatible          | True                                                                                                                                    |
      | requested_operation | {'operation': 'add_security_service', 'current_security_service': None, 'new_security_service': '50303c35-2c53-4d37-a0d9-61dfe3789569'} |
      +---------------------+-----------------------------------------------------------------------------------------------------------------------------------------+
