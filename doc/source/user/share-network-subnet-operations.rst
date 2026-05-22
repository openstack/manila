.. _share_network_subnet:

=======================================
Create and manage share network subnets
=======================================

.. contents:: :local:

A share network subnet stores network information to create and manage shares.
To create and manage your share network subnets, you can use ``openstack share``
client commands. You can create multiple subnets in a share network, and if you
do not specify an availability zone, the subnet you are creating will be
considered default by the Shared File Systems service. The default subnet
spans all availability zones. You cannot have more than one default subnet
per share network. During share server migration, metadata belonging to the
old share network subnet is ignored when moving to a new share network. Since
metadata updates are passed to backend driver, with migration of share network
these metadata updates will no longer be available to new share network.


.. important::

   In order to use share networks, the share type you choose must have the
   extra specification ``driver_handles_share_servers`` set to True.

Create a subnet in an existing share network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Create a subnet related to the given share network

   .. code-block:: console

      $ openstack share network subnet create sharenetwork1 \
         --availability-zone manila-zone-0 \
         --neutron-net-id 5edf25ef-73eb-4635-8be0-8246e7d7417b \
         --neutron-subnet-id 046cd84a-8938-4240-9ebd-ad5d8be10f20
      +--------------------+--------------------------------------+
      | Field              | Value                                |
      +--------------------+--------------------------------------+
      | id                 | 72cb7e51-7905-48fa-913f-23310d230f2c |
      | availability_zone  | manila-zone-0                        |
      | share_network_id   | 07727784-7af1-48d3-b116-804c4b93c5b4 |
      | share_network_name | sharenetwork1                        |
      | created_at         | 2026-04-03T04:57:26.313257           |
      | segmentation_id    | None                                 |
      | neutron_subnet_id  | 046cd84a-8938-4240-9ebd-ad5d8be10f20 |
      | updated_at         | None                                 |
      | neutron_net_id     | 5edf25ef-73eb-4635-8be0-8246e7d7417b |
      | ip_version         | None                                 |
      | cidr               | None                                 |
      | network_type       | None                                 |
      | mtu                | None                                 |
      | gateway            | None                                 |
      | metadata           | {}                                   |
      +--------------------+--------------------------------------+


#. Show the share network to verify if the created subnet is attached

   .. code-block:: console

      $ openstack share network show sharenetwork1
      +-----------------------------------+----------------------------------------------------------+
      | Field                             | Value                                                    |
      +-----------------------------------+----------------------------------------------------------+
      | id                                | 07727784-7af1-48d3-b116-804c4b93c5b4                     |
      | name                              | sharenetwork1                                            |
      | project_id                        | 58951a7d00fd46f9a98bd038ed5d9e09                         |
      | created_at                        | 2026-04-03T04:57:15.319508                               |
      | updated_at                        | None                                                     |
      | description                       | Share Network created for demo purposes                  |
      | status                            | active                                                   |
      | security_service_update_support   | True                                                     |
      | network_allocation_update_support | True                                                     |
      | share_network_subnets             |                                                          |
      |                                   | id = 08be4bbe-1ab0-40d0-aa03-3916604d9cae                |
      |                                   | availability_zone = None                                 |
      |                                   | created_at = 2026-04-03T04:57:15.439227                  |
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
      |                                   | id = 72cb7e51-7905-48fa-913f-23310d230f2c                |
      |                                   | availability_zone = manila-zone-0                        |
      |                                   | created_at = 2026-04-03T04:57:26.313257                  |
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


Show a share network subnet
~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Show an existent subnet in a given share network

   .. code-block:: console

      $ openstack share network subnet show sharenetwork1 \
         72cb7e51-7905-48fa-913f-23310d230f2c
      +--------------------+--------------------------------------+
      | Field              | Value                                |
      +--------------------+--------------------------------------+
      | id                 | 72cb7e51-7905-48fa-913f-23310d230f2c |
      | availability_zone  | manila-zone-0                        |
      | share_network_id   | 07727784-7af1-48d3-b116-804c4b93c5b4 |
      | share_network_name | sharenetwork1                        |
      | created_at         | 2026-04-03T04:57:26.313257           |
      | segmentation_id    | None                                 |
      | neutron_subnet_id  | 046cd84a-8938-4240-9ebd-ad5d8be10f20 |
      | updated_at         | None                                 |
      | neutron_net_id     | 5edf25ef-73eb-4635-8be0-8246e7d7417b |
      | ip_version         | None                                 |
      | cidr               | None                                 |
      | network_type       | None                                 |
      | mtu                | None                                 |
      | gateway            | None                                 |
      | properties         |                                      |
      +--------------------+--------------------------------------+

Delete a share network subnet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Delete a specific share network subnet

   .. code-block:: console

      $ openstack share network subnet delete sharenetwork1 \
         72cb7e51-7905-48fa-913f-23310d230f2c

#. Verify that it has been deleted

   .. code-block:: console

      $ openstack share network show sharenetwork1
      +-----------------------------------+----------------------------------------------------------+
      | Field                             | Value                                                    |
      +-----------------------------------+----------------------------------------------------------+
      | id                                | 07727784-7af1-48d3-b116-804c4b93c5b4                     |
      | name                              | sharenetwork1                                            |
      | project_id                        | 58951a7d00fd46f9a98bd038ed5d9e09                         |
      | created_at                        | 2026-04-03T04:57:15.319508                               |
      | updated_at                        | None                                                     |
      | description                       | Share Network created for demo purposes                  |
      | status                            | active                                                   |
      | security_service_update_support   | True                                                     |
      | network_allocation_update_support | True                                                     |
      | share_network_subnets             |                                                          |
      |                                   | id = 08be4bbe-1ab0-40d0-aa03-3916604d9cae                |
      |                                   | availability_zone = None                                 |
      |                                   | created_at = 2026-04-03T04:57:15.439227                  |
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

Share network subnet metadata
-----------------------------

* Set metadata items on your share network subnet during creation

  .. code-block:: console

     $ openstack share network subnet create sharenetwork1 \
        --property key1=value1 --property key2=value2
     +--------------------+--------------------------------------+
     | Field              | Value                                |
     +--------------------+--------------------------------------+
     | id                 | 245dd4af-b1cc-4aeb-8f7d-898e16d4d632 |
     | availability_zone  | None                                 |
     | share_network_id   | 07727784-7af1-48d3-b116-804c4b93c5b4 |
     | share_network_name | sharenetwork1                        |
     | created_at         | 2026-04-03T04:58:02.811583           |
     | segmentation_id    | None                                 |
     | neutron_subnet_id  | None                                 |
     | updated_at         | None                                 |
     | neutron_net_id     | None                                 |
     | ip_version         | None                                 |
     | cidr               | None                                 |
     | network_type       | None                                 |
     | mtu                | None                                 |
     | gateway            | None                                 |
     | metadata           | {'key1': 'value1', 'key2': 'value2'} |
     +--------------------+--------------------------------------+


* Set metadata items on your share network subnet

  .. code-block:: console

     $ openstack share network subnet set sharenetwork1 \
        72cb7e51-7905-48fa-913f-23310d230f2c --property key1=value1 \
        --property key2=value2


* Unset share network subnet metadata

  .. code-block:: console

     $ openstack share network subnet unset sharenetwork1 \
        72cb7e51-7905-48fa-913f-23310d230f2c --property key1
