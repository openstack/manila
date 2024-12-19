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

      clouduser1@client:~$ openstack share type list
      +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+
      | ID                                   | Name       | Visibility | Is Default | Required Extra Specs                 | Optional Extra Specs                      | Description |
      +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+
      | 61c7e7d2-ce74-4b50-9a3d-a89f7c51b9e9 | default    | public     | True       | driver_handles_share_servers : False | snapshot_support : True                   | None        |
      |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
      |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
      |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
      | 8867fc92-3193-4c6d-8248-a6ba10aa974b | dhss_false | public     | False      | driver_handles_share_servers : False | snapshot_support : True                   | None        |
      |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
      |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
      |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
      | 4d754228-5b5d-4632-8f96-0c27dcb7968f | dhss_true  | public     | False      | driver_handles_share_servers : True  | snapshot_support : True                   | None        |
      |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
      |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
      |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
      +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+

   In this example, three share types are available.


#. To use a share type that specifies driver_handles_share_servers=True
   capability, you must create a "share network" on which to export the
   share.

   .. code-block:: console

    clouduser1@client:~$ openstack subnet list
    +--------------------------------------+---------------------+--------------------------------------+---------------------+
    | ID                                   | Name                | Network                              | Subnet              |
    +--------------------------------------+---------------------+--------------------------------------+---------------------+
    | 01efb9d0-4c5f-424a-8402-b3bf19d0e4a2 | shared-subnet       | b8b3fedf-f788-4ba4-bf55-24521a20e671 | 192.168.233.0/24    |
    | 54a3188e-8bf2-461a-8b70-0d63f05810a6 | private-subnet      | 0bea5e39-81ce-4d6f-845d-ce5e87dad7d3 | 10.0.0.0/26         |
    | 6d1b41b2-8b39-482d-8e46-10bec65cdc99 | ipv6-public-subnet  | 9d25eb3b-d76c-4429-b788-a3dab0f2c24d | 2001:db8::/64       |
    | 8805a23b-b35e-42fe-8502-4f4bc58d23f7 | public-subnet       | 9d25eb3b-d76c-4429-b788-a3dab0f2c24d | 172.24.4.0/24       |
    | 9f8ae84a-5375-42f7-aa1b-eb3b697e8e3a | ipv6-private-subnet | 0bea5e39-81ce-4d6f-845d-ce5e87dad7d3 | fda4:5834:1c78::/64 |
    +--------------------------------------+---------------------+--------------------------------------+---------------------+



#. Create a "share network" from a private tenant network:

   .. code-block:: console

    clouduser1@client:~$ openstack share network create --name mynet \
                        --neutron-net-id 0bea5e39-81ce-4d6f-845d-ce5e87dad7d3 \
                        --neutron-subnet-id 54a3188e-8bf2-461a-8b70-0d63f05810a6
    +-----------------------------------+----------------------------------------------------------+
    | Field                             | Value                                                    |
    +-----------------------------------+----------------------------------------------------------+
    | created_at                        | 2025-04-16T18:39:17.582629                               |
    | description                       | None                                                     |
    | id                                | b6cc0aa0-c6bf-4c28-9566-a4bff93382d9                     |
    | name                              | mynet                                                    |
    | network_allocation_update_support | True                                                     |
    | project_id                        | 138d700333eb46cfb36b5a9659704759                         |
    | security_service_update_support   | True                                                     |
    | share_network_subnets             |                                                          |
    |                                   | id = 4114b63b-4932-4082-b5c9-e50dc839d3c9                |
    |                                   | availability_zone = None                                 |
    |                                   | created_at = 2025-04-16T18:39:17.607997                  |
    |                                   | updated_at = None                                        |
    |                                   | segmentation_id = None                                   |
    |                                   | neutron_net_id = 0bea5e39-81ce-4d6f-845d-ce5e87dad7d3    |
    |                                   | neutron_subnet_id = 54a3188e-8bf2-461a-8b70-0d63f05810a6 |
    |                                   | ip_version = None                                        |
    |                                   | cidr = None                                              |
    |                                   | network_type = None                                      |
    |                                   | mtu = None                                               |
    |                                   | gateway = None                                           |
    |                                   | metadata = {}                                            |
    | status                            | active                                                   |
    | updated_at                        | None                                                     |
    +-----------------------------------+----------------------------------------------------------+


    clouduser1@client:~$  openstack share network list
    +--------------------------------------+-------+
    | ID                                   | Name  |
    +--------------------------------------+-------+
    | b6cc0aa0-c6bf-4c28-9566-a4bff93382d9 | mynet |
    +--------------------------------------+-------+



#. Create the share:

   .. code-block:: console

    clouduser1@client:~$ openstack share create nfs 1 --name software_share \
                         --share-network mynet --share-type dhss_true
    +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
    | Field                                 | Value                                                                                                                |
    +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
    | access_rules_status                   | active                                                                                                               |
    | availability_zone                     | manila-zone-2                                                                                                        |
    | create_share_from_snapshot_support    | True                                                                                                                 |
    | created_at                            | 2025-04-22T16:00:19.973764                                                                                           |
    | description                           | None                                                                                                                 |
    | export_locations                      |                                                                                                                      |
    |                                       | id = 208c9cb5-853d-41c2-82ae-42c10c11d226                                                                            |
    |                                       | path = 10.0.0.10:/path/to/fake/share/share_18b84ece_fb8e_438c_b89b_bb2e7c69a5a0_013ca955_c1ca_4817_b053_d153e6bb5253 |
    |                                       | preferred = True                                                                                                     |
    |                                       | metadata = {}                                                                                                        |
    |                                       | id = 5f2f0201-4d68-48c9-a650-be59692a495f                                                                            |
    |                                       | path = 10.0.0.11:/path/to/fake/share/share_18b84ece_fb8e_438c_b89b_bb2e7c69a5a0_013ca955_c1ca_4817_b053_d153e6bb5253 |
    |                                       | preferred = False                                                                                                    |
    |                                       | metadata = {}                                                                                                        |
    | has_replicas                          | False                                                                                                                |
    | id                                    | 18b84ece-fb8e-438c-b89b-bb2e7c69a5a0                                                                                 |
    | is_public                             | False                                                                                                                |
    | is_soft_deleted                       | False                                                                                                                |
    | mount_snapshot_support                | True                                                                                                                 |
    | name                                  | software_share                                                                                                       |
    | progress                              | 100%                                                                                                                 |
    | project_id                            | 138d700333eb46cfb36b5a9659704759                                                                                     |
    | properties                            |                                                                                                                      |
    | replication_type                      | None                                                                                                                 |
    | revert_to_snapshot_support            | True                                                                                                                 |
    | scheduled_to_be_deleted_at            | None                                                                                                                 |
    | share_group_id                        | None                                                                                                                 |
    | share_network_id                      | b6cc0aa0-c6bf-4c28-9566-a4bff93382d9                                                                                 |
    | share_proto                           | NFS                                                                                                                  |
    | share_type                            | 4d754228-5b5d-4632-8f96-0c27dcb7968f                                                                                 |
    | share_type_name                       | dhss_true                                                                                                            |
    | size                                  | 1                                                                                                                    |
    | snapshot_id                           | None                                                                                                                 |
    | snapshot_support                      | True                                                                                                                 |
    | source_backup_id                      | None                                                                                                                 |
    | source_share_group_snapshot_member_id | None                                                                                                                 |
    | status                                | available                                                                                                            |
    | task_state                            | None                                                                                                                 |
    | user_id                               | c01b2bd0b56949508d27aebdf04c6d69                                                                                     |
    | volume_type                           | dhss_true                                                                                                            |
    +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+


#. View the status of the share:

   .. code-block:: console

    clouduser1@client:~$ openstack share list
    +--------------------------------------+------------------+------+-------------+--------+-----------+-----------------+------+-------------------+
    | ID                                   | Name             | Size | Share Proto | Status | Is Public | Share Type Name | Host | Availability Zone |
    +--------------------------------------+------------------+------+-------------+--------+-----------+-----------------+------+-------------------+
    | 18b84ece-fb8e-438c-b89b-bb2e7c69a5a0 | software_share   |    1 | NFS         | error  | False     | dhss_true       |      | None              |
    +--------------------------------------+------------------+------+-------------+--------+-----------+-----------------+------+-------------------+


   In this example, an error occurred during the share creation.


#. To view the generated user message, use the ``message-list`` command.
   Use ``--resource-id`` to filter messages for a specific share
   resource.

   .. code-block:: console

    clouduser1@client:~$ openstack share message list
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+
    | ID                                   | Resource Type | Resource ID                          | Action ID | User Message                                        | Detail ID | Created At                 |
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+
    | 8fe74a26-f57d-4961-8435-5ea8ccf05946 | SHARE         | 18b84ece-fb8e-438c-b89b-bb2e7c69a5a0 | 001       | allocate host: No storage could be allocated for    | 008       | 2025-04-22T20:16:50.207084 |
    |                                      |               |                                      |           | this share request, Capabilities filter didn't      |           |                            |
    |                                      |               |                                      |           | succeed.                                            |           |                            |
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+



   In User Message column, you can see that the Shared File System service
   failed to create the share because of a capabilities mismatch.


#. To view more information, use the ``message-show`` command,
   followed by the ID of the message from the message-list command:

   .. code-block:: console

    clouduser1@client:~$ openstack share message-show 8fe74a26-f57d-4961-8435-5ea8ccf05946
    +---------------+----------------------------------------------------------------------------------------------------------+
    | Field         | Value                                                                                                    |
    +---------------+----------------------------------------------------------------------------------------------------------+
    | id            | 8fe74a26-f57d-4961-8435-5ea8ccf05946                                                                     |
    | resource_type | SHARE                                                                                                    |
    | resource_id   | 18b84ece-fb8e-438c-b89b-bb2e7c69a5a0                                                                     |
    | action_id     | 001                                                                                                      |
    | user_message  | allocate host: No storage could be allocated for this share request, Capabilities filter didn't succeed. |
    | message_level | ERROR                                                                                                    |
    | detail_id     | 008                                                                                                      |
    | created_at    | 2025-04-22T20:16:50.207084                                                                               |
    | expires_at    | 2025-05-22T20:16:50.000000                                                                               |
    | request_id    | req-1621b77d-0abb-4c90-9e61-8809214f58a6                                                                 |
    +---------------+----------------------------------------------------------------------------------------------------------+


   As the cloud user, you know the related specs your share type has, so you can
   review the share types available. The difference between the two share types
   is the value of driver_handles_share_servers:

   .. code-block:: console

    clouduser1@client:~$ openstack share type list
    +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+
    | ID                                   | Name       | Visibility | Is Default | Required Extra Specs                 | Optional Extra Specs                      | Description |
    +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+
    | 61c7e7d2-ce74-4b50-9a3d-a89f7c51b9e9 | default    | public     | True       | driver_handles_share_servers : False | snapshot_support : True                   | None        |
    |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
    |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
    |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
    | 8867fc92-3193-4c6d-8248-a6ba10aa974b | dhss_false | public     | False      | driver_handles_share_servers : False | snapshot_support : True                   | None        |
    |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
    |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
    |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
    | 4d754228-5b5d-4632-8f96-0c27dcb7968f | dhss_true  | public     | False      | driver_handles_share_servers : True  | snapshot_support : True                   | None        |
    |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
    |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
    |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
    +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+



#. Create a share with the other available share type:

   .. code-block:: console

    clouduser1@client:~$ openstack share create nfs 1 --name software_share \
                        --share-network mynet --share-type dhss_false
    +---------------------------------------+--------------------------------------+
    | Field                                 | Value                                |
    +---------------------------------------+--------------------------------------+
    | access_rules_status                   | active                               |
    | availability_zone                     | None                                 |
    | create_share_from_snapshot_support    | True                                 |
    | created_at                            | 2025-04-22T20:34:04.627679           |
    | description                           | None                                 |
    | has_replicas                          | False                                |
    | id                                    | 010e4c5b-d40a-4691-a7cb-68c3b3950523 |
    | is_public                             | False                                |
    | is_soft_deleted                       | False                                |
    | metadata                              | {}                                   |
    | mount_snapshot_support                | True                                 |
    | name                                  | software_share                       |
    | progress                              | None                                 |
    | project_id                            | 138d700333eb46cfb36b5a9659704759     |
    | replication_type                      | None                                 |
    | revert_to_snapshot_support            | True                                 |
    | scheduled_to_be_deleted_at            | None                                 |
    | share_group_id                        | None                                 |
    | share_network_id                      | b6cc0aa0-c6bf-4c28-9566-a4bff93382d9 |
    | share_proto                           | NFS                                  |
    | share_type                            | 8867fc92-3193-4c6d-8248-a6ba10aa974b |
    | share_type_name                       | dhss_false                           |
    | size                                  | 1                                    |
    | snapshot_id                           | None                                 |
    | snapshot_support                      | True                                 |
    | source_backup_id                      | None                                 |
    | source_share_group_snapshot_member_id | None                                 |
    | status                                | creating                             |
    | task_state                            | None                                 |
    | user_id                               | c01b2bd0b56949508d27aebdf04c6d69     |
    | volume_type                           | dhss_false                           |
    +---------------------------------------+--------------------------------------+



   In this example, the second share creation attempt fails.


#. View the user support message:

   .. code-block:: console

    clouduser1@client:~$ openstack share list
    +--------------------------------------+------------------+------+-------------+--------+-----------+-----------------+------+-------------------+
    | ID                                   | Name             | Size | Share Proto | Status | Is Public | Share Type Name | Host | Availability Zone |
    +--------------------------------------+------------------+------+-------------+--------+-----------+-----------------+------+-------------------+
    | 18b84ece-fb8e-438c-b89b-bb2e7c69a5a0 | software_share   |    1 | NFS         | error  | False     | dhss_true       |      | None              |
    | 010e4c5b-d40a-4691-a7cb-68c3b3950523 | software_share   |    1 | NFS         | error  | False     | dhss_false      |      | manila-zone-1     |
    +--------------------------------------+------------------+------+-------------+--------+-----------+-----------------+------+-------------------+


    clouduser1@client:~$ openstack share message list
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+
    | ID                                   | Resource Type | Resource ID                          | Action ID | User Message                                        | Detail ID | Created At                 |
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+
    | 50a401e8-c30a-4369-8a35-68a019d19c76 | SHARE         | 010e4c5b-d40a-4691-a7cb-68c3b3950523 | 002       | create: Driver does not expect share-network to be  | 003       | 2025-04-22T20:34:04.810870 |
    |                                      |               |                                      |           | provided with current configuration.                |           |                            |
    | 8fe74a26-f57d-4961-8435-5ea8ccf05946 | SHARE         | 18b84ece-fb8e-438c-b89b-bb2e7c69a5a0 | 001       | allocate host: No storage could be allocated for    | 008       | 2025-04-22T20:16:50.207084 |
    |                                      |               |                                      |           | this share request, Capabilities filter didn't      |           |                            |
    |                                      |               |                                      |           | succeed.                                            |           |                            |
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+


   You can see that the service does not expect a share network for
   the share type used.
   Without consulting the administrator, you can discover that the
   administrator has not made available a storage back end that supports
   exporting shares directly on to your private neutron network.


#. Create the share without the ``--share-network`` parameter:

   .. code-block:: console

    clouduser1@client:~$ openstack share create nfs 1 --name software_share \
                        --share-type dhss_false
    +---------------------------------------+--------------------------------------+
    | Field                                 | Value                                |
    +---------------------------------------+--------------------------------------+
    | access_rules_status                   | active                               |
    | availability_zone                     | None                                 |
    | create_share_from_snapshot_support    | True                                 |
    | created_at                            | 2025-04-22T21:48:37.025207           |
    | description                           | None                                 |
    | has_replicas                          | False                                |
    | id                                    | feec61e2-4166-4ca3-8d59-a8d13f78535e |
    | is_public                             | False                                |
    | is_soft_deleted                       | False                                |
    | metadata                              | {}                                   |
    | mount_snapshot_support                | True                                 |
    | name                                  | software_share                       |
    | progress                              | None                                 |
    | project_id                            | 138d700333eb46cfb36b5a9659704759     |
    | replication_type                      | None                                 |
    | revert_to_snapshot_support            | True                                 |
    | scheduled_to_be_deleted_at            | None                                 |
    | share_group_id                        | None                                 |
    | share_network_id                      | None                                 |
    | share_proto                           | NFS                                  |
    | share_type                            | 8867fc92-3193-4c6d-8248-a6ba10aa974b |
    | share_type_name                       | dhss_false                           |
    | size                                  | 1                                    |
    | snapshot_id                           | None                                 |
    | snapshot_support                      | True                                 |
    | source_backup_id                      | None                                 |
    | source_share_group_snapshot_member_id | None                                 |
    | status                                | creating                             |
    | task_state                            | None                                 |
    | user_id                               | c01b2bd0b56949508d27aebdf04c6d69     |
    | volume_type                           | dhss_false                           |
    +---------------------------------------+--------------------------------------+



#. To ensure that the share was created successfully, use the `share list`
   command:

   .. code-block:: console

    clouduser1@client:~$ openstack share list
    +--------------------------------------+------------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
    | ID                                   | Name             | Size | Share Proto | Status    | Is Public | Share Type Name | Host | Availability Zone |
    +--------------------------------------+------------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
    | 18b84ece-fb8e-438c-b89b-bb2e7c69a5a0 | software_share   |    1 | NFS         | error     | False     | dhss_true       |      | None              |
    | feec61e2-4166-4ca3-8d59-a8d13f78535e | software_share   |    1 | NFS         | available | False     | dhss_false      |      | manila-zone-1     |
    | 010e4c5b-d40a-4691-a7cb-68c3b3950523 | software_share   |    1 | NFS         | error     | False     | dhss_false      |      | manila-zone-1     |
    +--------------------------------------+------------------+------+-------------+-----------+-----------+-----------------+------+-------------------+


#. Delete shares that failed to be created and corresponding support messages:

   .. code-block:: console

    clouduser1@client:~$ openstack share delete \
                         18b84ece-fb8e-438c-b89b-bb2e7c69a5a0 \
                         010e4c5b-d40a-4691-a7cb-68c3b3950523
    clouduser1@client:~$ openstack share message list
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+
    | ID                                   | Resource Type | Resource ID                          | Action ID | User Message                                        | Detail ID | Created At                 |
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+
    | 50a401e8-c30a-4369-8a35-68a019d19c76 | SHARE         | 010e4c5b-d40a-4691-a7cb-68c3b3950523 | 002       | create: Driver does not expect share-network to be  | 003       | 2025-04-22T20:34:04.810870 |
    |                                      |               |                                      |           | provided with current configuration.                |           |                            |
    | 8fe74a26-f57d-4961-8435-5ea8ccf05946 | SHARE         | 18b84ece-fb8e-438c-b89b-bb2e7c69a5a0 | 001       | allocate host: No storage could be allocated for    | 008       | 2025-04-22T20:16:50.207084 |
    |                                      |               |                                      |           | this share request, Capabilities filter didn't      |           |                            |
    |                                      |               |                                      |           | succeed.                                            |           |                            |
    +--------------------------------------+---------------+--------------------------------------+-----------+-----------------------------------------------------+-----------+----------------------------+


    clouduser1@client:~$ openstack share message delete \
                         50a401e8-c30a-4369-8a35-68a019d19c76 \
                         8fe74a26-f57d-4961-8435-5ea8ccf05946

    clouduser1@client:~$ openstack share message list
    +----+---------------+-------------+-----------+--------------+-----------+------------+
    | ID | Resource Type | Resource ID | Action ID | User Message | Detail ID | Created At |
    +----+---------------+-------------+-----------+--------------+-----------+------------+
    +----+---------------+-------------+-----------+--------------+-----------+------------+
