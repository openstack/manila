=====================================
Troubleshooting asynchronous failures
=====================================

The Shared File Systems service performs many user actions asynchronously.
For example, when a new share is created, the request is immediately
acknowledged with a response containing the metadata of the share.
Users can then query the resource and check the ``status`` attribute
of the share. Usually an ``...ing`` status indicates that actions are performed
asynchronously. For example, a new share's ``status`` attribute is set to
``creating`` by the service. If these asynchronous operations fail, the
resource's status will be set to ``error``. More information about the error
can be obtained with the help of the CLI client.

Scenario
~~~~~~~~
In this example, the user wants to create a share to host software libraries
on several virtual machines. The example deliberately introduces two share
creation failures to illustrate how to use the command line to retrieve user
support messages.


#. In order to create a share, you need to specify the share type that meets
   your requirements. Cloud administrators create share types; see these
   available share types:

   .. code-block:: console

      clouduser1@client:~$ manila type-list
      +--------------------------------------+-------------+------------+------------+--------------------------------------+--------------------------------------------+-------------+
      | ID                                   | Name        | visibility | is_default | required_extra_specs                 | optional_extra_specs                       | Description |
      +--------------------------------------+-------------+------------+------------+--------------------------------------+--------------------------------------------+-------------+
      | 1cf5d45a-61b3-44d1-8ec7-89a21f51a4d4 | dhss_false  | public     | YES        | driver_handles_share_servers : False | create_share_from_snapshot_support : True  | None        |
      |                                      |             |            |            |                                      | mount_snapshot_support : False             |             |
      |                                      |             |            |            |                                      | revert_to_snapshot_support : False         |             |
      |                                      |             |            |            |                                      | snapshot_support : True                    |             |
      | 277c1089-127f-426e-9b12-711845991ea1 | dhss_true   | public     | -          | driver_handles_share_servers : True  | create_share_from_snapshot_support : True  | None        |
      |                                      |             |            |            |                                      | mount_snapshot_support : False             |             |
      |                                      |             |            |            |                                      | revert_to_snapshot_support : False         |             |
      |                                      |             |            |            |                                      | snapshot_support : True                    |             |
      +--------------------------------------+-------------+------------+------------+--------------------------------------+--------------------------------------------+-------------+


   In this example, two share types are available.


#. To use a share type that specifies driver_handles_share_servers=True
   capability, you must create a "share network" on which to export the
   share.

   .. code-block:: console

    clouduser1@client:~$ openstack subnet list
    +--------------------------------------+---------------------+--------------------------------------+---------------------+
    | ID                                   | Name                | Network                              | Subnet              |
    +--------------------------------------+---------------------+--------------------------------------+---------------------+
    | 78c6ac57-bba7-4922-ab81-16cde31c2d06 | private-subnet      | 74d5cfb3-5dd0-43f7-b1b2-5b544cb16212 | 10.0.0.0/26         |
    | a344682c-718d-4825-a87a-3622b4d3a771 | ipv6-private-subnet | 74d5cfb3-5dd0-43f7-b1b2-5b544cb16212 | fd36:18fc:a8e9::/64 |
    +--------------------------------------+---------------------+--------------------------------------+---------------------+



#. Create a "share network" from a private tenant network:

   .. code-block:: console

    clouduser1@client:~$ manila share-network-create --name mynet --neutron-net-id 74d5cfb3-5dd0-43f7-b1b2-5b544cb16212 --neutron-subnet-id 78c6ac57-bba7-4922-ab81-16cde31c2d06
    +-------------------+--------------------------------------+
    | Property          | Value                                |
    +-------------------+--------------------------------------+
    | network_type      | None                                 |
    | name              | mynet                                |
    | segmentation_id   | None                                 |
    | created_at        | 2018-10-09T21:32:22.485399           |
    | neutron_subnet_id | 78c6ac57-bba7-4922-ab81-16cde31c2d06 |
    | updated_at        | None                                 |
    | mtu               | None                                 |
    | gateway           | None                                 |
    | neutron_net_id    | 74d5cfb3-5dd0-43f7-b1b2-5b544cb16212 |
    | ip_version        | None                                 |
    | cidr              | None                                 |
    | project_id        | cadd7139bc3148b8973df097c0911016     |
    | id                | 0b0fc320-d4b5-44a1-a1ae-800c56de550c |
    | description       | None                                 |
    +-------------------+--------------------------------------+

    clouduser1@client:~$ manila share-network-list
    +--------------------------------------+-------+
    | id                                   | name  |
    +--------------------------------------+-------+
    | 6c7ef9ef-3591-48b6-b18a-71a03059edd5 | mynet |
    +--------------------------------------+-------+


#. Create the share:

   .. code-block:: console

    clouduser1@client:~$ manila create nfs 1 --name software_share --share-network mynet --share-type dhss_true
    +---------------------------------------+--------------------------------------+
    | Property                              | Value                                |
    +---------------------------------------+--------------------------------------+
    | status                                | creating                             |
    | share_type_name                       | dhss_true                            |
    | description                           | None                                 |
    | availability_zone                     | None                                 |
    | share_network_id                      | 6c7ef9ef-3591-48b6-b18a-71a03059edd5 |
    | share_server_id                       | None                                 |
    | share_group_id                        | None                                 |
    | host                                  |                                      |
    | revert_to_snapshot_support            | False                                |
    | access_rules_status                   | active                               |
    | snapshot_id                           | None                                 |
    | create_share_from_snapshot_support    | False                                |
    | is_public                             | False                                |
    | task_state                            | None                                 |
    | snapshot_support                      | False                                |
    | id                                    | 243f3a51-0624-4bdd-950e-7ed190b53b67 |
    | size                                  | 1                                    |
    | source_share_group_snapshot_member_id | None                                 |
    | user_id                               | 61aef4895b0b41619e67ae83fba6defe     |
    | name                                  | software_share                       |
    | share_type                            | 277c1089-127f-426e-9b12-711845991ea1 |
    | has_replicas                          | False                                |
    | replication_type                      | None                                 |
    | created_at                            | 2018-10-09T21:12:21.000000           |
    | share_proto                           | NFS                                  |
    | mount_snapshot_support                | False                                |
    | project_id                            | cadd7139bc3148b8973df097c0911016     |
    | metadata                              | {}                                   |
    +---------------------------------------+--------------------------------------+


#. View the status of the share:

   .. code-block:: console

      clouduser1@client:~$ manila list
      +--------------------------------------+----------------+------+-------------+--------+-----------+-----------------+------+-------------------+
      | ID                                   | Name           | Size | Share Proto | Status | Is Public | Share Type Name | Host | Availability Zone |
      +--------------------------------------+----------------+------+-------------+--------+-----------+-----------------+------+-------------------+
      | 243f3a51-0624-4bdd-950e-7ed190b53b67 | software_share | 1    | NFS         | error  | False     | dhss_true       |      | None              |
      +--------------------------------------+----------------+------+-------------+--------+-----------+-----------------+------+-------------------+

   In this example, an error occurred during the share creation.


#. To view the generated user message, use the ``message-list`` command.
   Use ``--resource-id`` to filter messages for a specific share
   resource.

   .. code-block:: console

      clouduser1@client:~$ manila message-list
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+
      | ID                                   | Resource Type | Resource ID                          | Action ID | User Message                                                                                             | Detail ID | Created At                 |
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+
      | 7d411c3c-46d9-433f-9e21-c04ca30b209c | SHARE         | 243f3a51-0624-4bdd-950e-7ed190b53b67 | 001       | allocate host: No storage could be allocated for this share request, Capabilities filter didn't succeed. | 008       | 2018-10-09T21:12:21.000000 |
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+

   In User Message column, you can see that the Shared File System service
   failed to create the share because of a capabilities mismatch.


#. To view more information, use the ``message-show`` command,
   followed by the ID of the message from the message-list command:

   .. code-block:: console

      clouduser1@client:~$ manila message-show 7d411c3c-46d9-433f-9e21-c04ca30b209c
      +---------------+----------------------------------------------------------------------------------------------------------+
      | Property      | Value                                                                                                    |
      +---------------+----------------------------------------------------------------------------------------------------------+
      | request_id    | req-0a875292-6c52-458b-87d4-1f945556feac                                                                 |
      | detail_id     | 008                                                                                                      |
      | expires_at    | 2018-11-08T21:12:21.000000                                                                               |
      | resource_id   | 243f3a51-0624-4bdd-950e-7ed190b53b67                                                                     |
      | user_message  | allocate host: No storage could be allocated for this share request, Capabilities filter didn't succeed. |
      | created_at    | 2018-10-09T21:12:21.000000                                                                               |
      | message_level | ERROR                                                                                                    |
      | id            | 7d411c3c-46d9-433f-9e21-c04ca30b209c                                                                     |
      | resource_type | SHARE                                                                                                    |
      | action_id     | 001                                                                                                      |
      +---------------+----------------------------------------------------------------------------------------------------------+

   As the cloud user, you know the related specs your share type has, so you can
   review the share types available. The difference between the two share types
   is the value of driver_handles_share_servers:

   .. code-block:: console

    clouduser1@client:~$ manila type-list
    +--------------------------------------+-------------+------------+------------+--------------------------------------+--------------------------------------------+-------------+
    | ID                                   | Name        | visibility | is_default | required_extra_specs                 | optional_extra_specs                       | Description |
    +--------------------------------------+-------------+------------+------------+--------------------------------------+--------------------------------------------+-------------+
    | 1cf5d45a-61b3-44d1-8ec7-89a21f51a4d4 | dhss_false  | public     | YES        | driver_handles_share_servers : False | create_share_from_snapshot_support : True  | None        |
    |                                      |             |            |            |                                      | mount_snapshot_support : False             |             |
    |                                      |             |            |            |                                      | revert_to_snapshot_support : False         |             |
    |                                      |             |            |            |                                      | snapshot_support : True                    |             |
    | 277c1089-127f-426e-9b12-711845991ea1 | dhss_true   | public     | -          | driver_handles_share_servers : True  | create_share_from_snapshot_support : True  | None        |
    |                                      |             |            |            |                                      | mount_snapshot_support : False             |             |
    |                                      |             |            |            |                                      | revert_to_snapshot_support : False         |             |
    |                                      |             |            |            |                                      | snapshot_support : True                    |             |
    +--------------------------------------+-------------+------------+------------+--------------------------------------+--------------------------------------------+-------------+


#. Create a share with the other available share type:

   .. code-block:: console

      clouduser1@client:~$ manila create nfs 1 --name software_share --share-network mynet --share-type dhss_false
      +---------------------------------------+--------------------------------------+
      | Property                              | Value                                |
      +---------------------------------------+--------------------------------------+
      | status                                | creating                             |
      | share_type_name                       | dhss_false                           |
      | description                           | None                                 |
      | availability_zone                     | None                                 |
      | share_network_id                      | 6c7ef9ef-3591-48b6-b18a-71a03059edd5 |
      | share_group_id                        | None                                 |
      | revert_to_snapshot_support            | False                                |
      | access_rules_status                   | active                               |
      | snapshot_id                           | None                                 |
      | create_share_from_snapshot_support    | True                                 |
      | is_public                             | False                                |
      | task_state                            | None                                 |
      | snapshot_support                      | True                                 |
      | id                                    | 2d03d480-7cba-4122-ac9d-edc59c8df698 |
      | size                                  | 1                                    |
      | source_share_group_snapshot_member_id | None                                 |
      | user_id                               | 5c7bdb6eb0504d54a619acf8375c08ce     |
      | name                                  | software_share                       |
      | share_type                            | 1cf5d45a-61b3-44d1-8ec7-89a21f51a4d4 |
      | has_replicas                          | False                                |
      | replication_type                      | None                                 |
      | created_at                            | 2018-10-09T21:24:40.000000           |
      | share_proto                           | NFS                                  |
      | mount_snapshot_support                | False                                |
      | project_id                            | cadd7139bc3148b8973df097c0911016     |
      | metadata                              | {}                                   |
      +---------------------------------------+--------------------------------------+

   In this example, the second share creation attempt fails.


#. View the user support message:

   .. code-block:: console

      clouduser1@client:~$ manila list
      +--------------------------------------+----------------+------+-------------+--------+-----------+-----------------+------+-------------------+
      | ID                                   | Name           | Size | Share Proto | Status | Is Public | Share Type Name | Host | Availability Zone |
      +--------------------------------------+----------------+------+-------------+--------+-----------+-----------------+------+-------------------+
      | 2d03d480-7cba-4122-ac9d-edc59c8df698 | software_share | 1    | NFS         | error  | False     | dhss_false      |      | nova              |
      | 243f3a51-0624-4bdd-950e-7ed190b53b67 | software_share | 1    | NFS         | error  | False     | dhss_true       |      | None              |
      +--------------------------------------+----------------+------+-------------+--------+-----------+-----------------+------+-------------------+

      clouduser1@client:~$ manila message-list
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+
      | ID                                   | Resource Type | Resource ID                          | Action ID | User Message                                                                                             | Detail ID | Created At                 |
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+
      | ed7e02a2-0cdb-4ff9-b64f-e4d2ec1ef069 | SHARE         | 2d03d480-7cba-4122-ac9d-edc59c8df698 | 002       | create: Driver does not expect share-network to be provided with current configuration.                  | 003       | 2018-10-09T21:24:40.000000 |
      | 7d411c3c-46d9-433f-9e21-c04ca30b209c | SHARE         | 243f3a51-0624-4bdd-950e-7ed190b53b67 | 001       | allocate host: No storage could be allocated for this share request, Capabilities filter didn't succeed. | 008       | 2018-10-09T21:12:21.000000 |
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+

   You can see that the service does not expect a share network for
   the share type used.
   Without consulting the administrator, you can discover that the
   administrator has not made available a storage back end that supports
   exporting shares directly on to your private neutron network.


#. Create the share without the ``--share-network`` parameter:

   .. code-block:: console

      clouduser1@client:~$ manila create nfs 1 --name software_share --share-type dhss_false
      +---------------------------------------+--------------------------------------+
      | Property                              | Value                                |
      +---------------------------------------+--------------------------------------+
      | status                                | creating                             |
      | share_type_name                       | dhss_false                           |
      | description                           | None                                 |
      | availability_zone                     | None                                 |
      | share_network_id                      | None                                 |
      | share_group_id                        | None                                 |
      | revert_to_snapshot_support            | False                                |
      | access_rules_status                   | active                               |
      | snapshot_id                           | None                                 |
      | create_share_from_snapshot_support    | True                                 |
      | is_public                             | False                                |
      | task_state                            | None                                 |
      | snapshot_support                      | True                                 |
      | id                                    | 4d3d7fcf-5fb7-4209-90eb-9e064659f46d |
      | size                                  | 1                                    |
      | source_share_group_snapshot_member_id | None                                 |
      | user_id                               | 5c7bdb6eb0504d54a619acf8375c08ce     |
      | name                                  | software_share                       |
      | share_type                            | 1cf5d45a-61b3-44d1-8ec7-89a21f51a4d4 |
      | has_replicas                          | False                                |
      | replication_type                      | None                                 |
      | created_at                            | 2018-10-09T21:25:40.000000           |
      | share_proto                           | NFS                                  |
      | mount_snapshot_support                | False                                |
      | project_id                            | cadd7139bc3148b8973df097c0911016     |
      | metadata                              | {}                                   |
      +---------------------------------------+--------------------------------------+


#. To ensure that the share was created successfully, use the `manila list`
   command:

   .. code-block:: console

      clouduser1@client:~$ manila list
      +--------------------------------------+----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
      | ID                                   | Name           | Size | Share Proto | Status    | Is Public | Share Type Name | Host | Availability Zone |
      +--------------------------------------+----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
      | 4d3d7fcf-5fb7-4209-90eb-9e064659f46d | software_share | 1    | NFS         | available | False     | dhss_false      |      | nova              |
      | 2d03d480-7cba-4122-ac9d-edc59c8df698 | software_share | 1    | NFS         | error     | False     | dhss_false      |      | nova              |
      | 243f3a51-0624-4bdd-950e-7ed190b53b67 | software_share | 1    | NFS         | error     | False     | dhss_true       |      | None              |
      +--------------------------------------+----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+

#. Delete shares that failed to be created and corresponding support messages:

   .. code-block:: console

      clouduser1@client:~$ manila delete 2d03d480-7cba-4122-ac9d-edc59c8df698 243f3a51-0624-4bdd-950e-7ed190b53b67
      clouduser1@client:~$ manila message-list
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+
      | ID                                   | Resource Type | Resource ID                          | Action ID | User Message                                                                                             | Detail ID | Created At                 |
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+
      | ed7e02a2-0cdb-4ff9-b64f-e4d2ec1ef069 | SHARE         | 2d03d480-7cba-4122-ac9d-edc59c8df698 | 002       | create: Driver does not expect share-network to be provided with current configuration.                  | 003       | 2018-10-09T21:24:40.000000 |
      | 7d411c3c-46d9-433f-9e21-c04ca30b209c | SHARE         | 243f3a51-0624-4bdd-950e-7ed190b53b67 | 001       | allocate host: No storage could be allocated for this share request, Capabilities filter didn't succeed. | 008       | 2018-10-09T21:12:21.000000 |
      +--------------------------------------+---------------+--------------------------------------+-----------+----------------------------------------------------------------------------------------------------------+-----------+----------------------------+

      clouduser1@client:~$ manila message-delete ed7e02a2-0cdb-4ff9-b64f-e4d2ec1ef069 7d411c3c-46d9-433f-9e21-c04ca30b209c

      clouduser1@client:~$ manila message-list
      +----+---------------+-------------+-----------+--------------+-----------+------------+
      | ID | Resource Type | Resource ID | Action ID | User Message | Detail ID | Created At |
      +----+---------------+-------------+-----------+--------------+-----------+------------+
      +----+---------------+-------------+-----------+--------------+-----------+------------+
