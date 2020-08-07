.. _share_network_subnet:

=======================================
Create and manage share network subnets
=======================================

.. contents:: :local:

A share network subnet stores network information to create and manage shares.
To create and manage your share network subnets, you can use ``manila`` client
commands. You can create multiple subnets in a share network, and if you do
not specify an availability zone, the subnet you are creating will be
considered default by the Shared File Systems service. The default subnet
spans all availability zones. You cannot have more than one default subnet
per share network.


.. important::

   In order to use share networks, the share type you choose must have the
   extra specification ``driver_handles_share_servers`` set to True.

Create a subnet in an existing share network
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Create a subnet related to the given share network

   .. code-block:: console

      $ manila share-network-subnet-create \
         sharenetwork1 \
         --availability-zone manila-zone-0 \
         --neutron-net-id a27160ca-5595-4c62-bf54-a04fb7b14316 \
         --neutron-subnet-id f043f4b0-c05e-493f-bbe9-99689e2187d2
      +--------------------+--------------------------------------+
      | Property           | Value                                |
      +--------------------+--------------------------------------+
      | id                 | be3ae5ad-a22c-494f-840e-5e3526e34e0f |
      | availability_zone  | manila-zone-0                        |
      | share_network_id   | 35f44d3c-8888-429e-b8c7-8a29dead6e5b |
      | share_network_name | sharenetwork1                        |
      | created_at         | 2019-10-09T04:54:48.000000           |
      | segmentation_id    | None                                 |
      | neutron_subnet_id  | f043f4b0-c05e-493f-bbe9-99689e2187d2 |
      | updated_at         | None                                 |
      | neutron_net_id     | a27160ca-5595-4c62-bf54-a04fb7b14316 |
      | ip_version         | None                                 |
      | cidr               | None                                 |
      | network_type       | None                                 |
      | mtu                | None                                 |
      | gateway            | None                                 |
      +--------------------+--------------------------------------+


#. Show the share network to verify if the created subnet is attached

   .. code-block:: console

      $ manila share-network-show sharenetwork1
      +-----------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | Property              | Value                                                                                                                                                                                                                                                                                                                                                                                        |
      +-----------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
      | id                    | 35f44d3c-8888-429e-b8c7-8a29dead6e5b                                                                                                                                                                                                                                                                                                                                                         |
      | name                  | sharenetwork1                                                                                                                                                                                                                                                                                                                                                                                |
      | project_id            | 8c2962a4832743469a336f7c179f7d34                                                                                                                                                                                                                                                                                                                                                             |
      | created_at            | 2019-10-09T04:19:31.000000                                                                                                                                                                                                                                                                                                                                                                   |
      | updated_at            | None                                                                                                                                                                                                                                                                                                                                                                                         |
      | description           | Share Network created for demo purposes                                                                                                                                                                                                                                                                                                                                                      |
      | share_network_subnets | [{'id': 'be3ae5ad-a22c-494f-840e-5e3526e34e0f', 'availability_zone': 'manila-zone-0', 'created_at': '2019-10-09T04:54:48.000000', 'updated_at': None, 'segmentation_id': None, 'neutron_net_id': 'a27160ca-5595-4c62-bf54-a04fb7b14316', 'neutron_subnet_id': 'f043f4b0-c05e-493f-bbe9-99689e2187d2', 'ip_version': None, 'cidr': None, 'network_type': None, 'mtu': None, 'gateway': None}] |
      +-----------------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+


Show a share network subnet
~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Show an existent subnet in a given share network

   .. code-block:: console

      $ manila share-network-subnet-show \
         sharenetwork1 \
         be3ae5ad-a22c-494f-840e-5e3526e34e0f
      +--------------------+--------------------------------------+
      | Property           | Value                                |
      +--------------------+--------------------------------------+
      | id                 | be3ae5ad-a22c-494f-840e-5e3526e34e0f |
      | availability_zone  | manila-zone-0                        |
      | share_network_id   | 35f44d3c-8888-429e-b8c7-8a29dead6e5b |
      | share_network_name | sharenetwork1                        |
      | created_at         | 2019-10-09T04:54:48.000000           |
      | segmentation_id    | None                                 |
      | neutron_subnet_id  | f043f4b0-c05e-493f-bbe9-99689e2187d2 |
      | updated_at         | None                                 |
      | neutron_net_id     | a27160ca-5595-4c62-bf54-a04fb7b14316 |
      | ip_version         | None                                 |
      | cidr               | None                                 |
      | network_type       | None                                 |
      | mtu                | None                                 |
      | gateway            | None                                 |
      +--------------------+--------------------------------------+

Delete a share network subnet
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#. Delete a specific share network subnet

   .. code-block:: console

      $ manila share-network-subnet-delete \
         sharenetwork1 \
         be3ae5ad-a22c-494f-840e-5e3526e34e0f

#. Verify that it has been deleted

   .. code-block:: console

      $ manila share-network-show sharenetwork1
      +-----------------------+-----------------------------------------+
      | Property              | Value                                   |
      +-----------------------+-----------------------------------------+
      | id                    | 35f44d3c-8888-429e-b8c7-8a29dead6e5b    |
      | name                  | sharenetwork1                           |
      | project_id            | 8c2962a4832743469a336f7c179f7d34        |
      | created_at            | 2019-10-09T04:19:31.000000              |
      | updated_at            | None                                    |
      | description           | Share Network created for demo purposes |
      | share_network_subnets | []                                      |
      +-----------------------+-----------------------------------------+
