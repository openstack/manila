.. _share:

========================
Create and manage shares
========================

.. contents:: :local:

General Concepts
----------------

A ``share`` is filesystem storage that you can create with manila. You can pick
a network protocol for the underlying storage, manage access and perform
lifecycle operations on the share via the ``manila`` command line tool.

Before we review the operations possible, lets take a look at certain
important terms:

- ``share network``: This is a network that your shares can be exported to.
  Exporting shares to your own self-service isolated networks allows manila to
  provide ``hard network path`` data isolation guarantees in a multi-tenant
  cloud. To do so, under the hood, manila creates isolated ``share
  servers``, and plugs them into your network. These share servers manage
  exports of your shares, and can connect to authentication domains that you
  determine. Manila performs all the lifecycle operations necessary on share
  servers, and you needn't worry about them. The important thing to note is
  that your cloud administrator must have made a share type with extra-spec
  ``driver_handles_share_servers=True`` for you to be able to use share
  networks and create shares on them. See :doc:`share-network-operations` and
  :doc:`share-network-subnet-operations` for more details.

- ``share type``: A share type is a template made available by your
  administrator. You must always specify a share type when creating a share,
  unless you would like to use the default share type. It's possible that
  your cloud administrator has not made a default share type accessible to
  you. Share types specify some capabilities for your use:

+------------------------------------+-------------------------+---------------------------------------------------------+
|             Capability             |     Possible values     |                       Consequence                       |
+====================================+=========================+=========================================================+
| driver_handles_share_servers       | true or false           | you can or cannot use share networks to create shares   |
+------------------------------------+-------------------------+---------------------------------------------------------+
| snapshot_support                   | true or false           | you can or cannot create snapshots of shares            |
+------------------------------------+-------------------------+---------------------------------------------------------+
| create_share_from_snapshot_support | true or false           | you can or cannot create clones of share snapshots      |
+------------------------------------+-------------------------+---------------------------------------------------------+
| revert_to_snapshot_support         | true or false           | you can or cannot revert your shares in-place to the    |
|                                    |                         | most recent snapshot                                    |
+------------------------------------+-------------------------+---------------------------------------------------------+
| mount_snapshot_support             | true or false           | you can or cannot export your snapshots and mount them  |
+------------------------------------+-------------------------+---------------------------------------------------------+
| replication_type                   | dr                      | you can create replicas for disaster recovery, only one |
|                                    |                         | active export allowed at a time                         |
|                                    +-------------------------+---------------------------------------------------------+
|                                    | readable                | you can create read-only replicas, only one writable    |
|                                    |                         | active export allowed at a time                         |
|                                    +-------------------------+---------------------------------------------------------+
|                                    | writable                | you can create read/write replicas, any number          |
|                                    |                         | of active exports per share                             |
+------------------------------------+-------------------------+---------------------------------------------------------+
| availability_zones                 | a list of one or        | shares are limited to these availability zones          |
|                                    | more availability zones |                                                         |
+------------------------------------+-------------------------+---------------------------------------------------------+
| mount_point_name_support           | true or false           | share can or cannot have customized export location     |
+------------------------------------+-------------------------+---------------------------------------------------------+
| encryption_support                 | share                   | share is encrypted with share encryption key            |
|                                    +-------------------------+---------------------------------------------------------+
|                                    | share_server            | share is encrypted with share server encryption key     |
+------------------------------------+-------------------------+---------------------------------------------------------+
| provisioning:mount_point_prefix    | string                  | prefix used for custom export location                  |
+------------------------------------+-------------------------+---------------------------------------------------------+

.. note::

   -  When ``replication_type`` extra specification is not present in the
      share type, you cannot create share replicas
   -  When the ``availability_zones`` extra specification is not present in
      the share type, the share type can be used in all availability zones of
      the cloud.
   -  When ``mount_point_name_support`` extra specification is not present in the
      share type, or is set to False, you cannot customize the export location.

- ``status`` of resources: Resources that you create or modify with manila
  may not be "available" immediately. The API service is designed to respond
  immediately and the resource being created or modified is worked upon by the
  rest of the service stack. To indicate the readiness of resources, there are
  several attributes on the resources themselves and the user can watch these
  fields to know the state of the resource. For example, the ``status`` attribute
  in shares can convey some busy states such as "creating", "extending", "shrinking",
  "migrating". These "-ing" states end in a "available" state if everything goes
  well. They may end up in an "error" state in case there is an issue. See
  :doc:`troubleshooting-asynchronous-failures` to determine if you can rectify
  these errors by yourself. If you cannot, consulting a more privileged user,
  usually a cloud administrator, might be useful.

- ``snapshot``: This is a point-in-time copy of a share. In manila, snapshots
  are meant to be crash consistent, however, you may need to quiesce any applications
  using the share to ensure that the snapshots are application consistent.
  Cloud administrators can enable or disable snapshots via share type extra
  specifications.

- ``security service``: This is an authentication domain that you define and associate
  with your share networks. It could be an Active Directory server, a Lightweight
  Directory Access Protocol server, or Kerberos. When used, access to shares can
  be controlled via these authentication domains. You may even combine multiple
  authentication domains.


Usage and Limits
----------------

* List the resource limits and usages that apply to your project

  .. code-block:: console

     $ manila absolute-limits
     +----------------------------+-------+
     | Name                       | Value |
     +----------------------------+-------+
     | maxTotalReplicaGigabytes   | 1000  |
     | maxTotalShareGigabytes     | 1000  |
     | maxTotalShareNetworks      | 10    |
     | maxTotalShareReplicas      | 100   |
     | maxTotalShareSnapshots     | 50    |
     | maxTotalShares             | 50    |
     | maxTotalSnapshotGigabytes  | 1000  |
     | totalReplicaGigabytesUsed  | 0     |
     | totalShareGigabytesUsed    | 4     |
     | totalShareNetworksUsed     | 1     |
     | totalShareReplicasUsed     | 0     |
     | totalShareSnapshotsUsed    | 1     |
     | totalSharesUsed            | 4     |
     | totalSnapshotGigabytesUsed | 1     |
     +----------------------------+-------+

Share types
-----------

* List share types

  .. code-block:: console

     $ openstack share type list
     +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+--------------------------------------------+---------------------------------------------------------+
     | ID                                   | Name                              | visibility | is_default | required_extra_specs                 | optional_extra_specs                       | Description                                             |
     +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+--------------------------------------------+---------------------------------------------------------+
     | af7b64ec-cdb3-4a5f-93c9-51672d72e172 | dhss_true                         | public     | -          | driver_handles_share_servers : True  | snapshot_support : True                    | None                                                    |
     |                                      |                                   |            |            |                                      | create_share_from_snapshot_support : True  |                                                         |
     |                                      |                                   |            |            |                                      | revert_to_snapshot_support : True          |                                                         |
     |                                      |                                   |            |            |                                      | mount_snapshot_support : True              |                                                         |
     | c39d3565-cee0-4a64-9e60-af06991ea4f7 | default                           | public     | YES        | driver_handles_share_servers : False | snapshot_support : True                    | None                                                    |
     |                                      |                                   |            |            |                                      | create_share_from_snapshot_support : True  |                                                         |
     |                                      |                                   |            |            |                                      | revert_to_snapshot_support : True          |                                                         |
     |                                      |                                   |            |            |                                      | mount_snapshot_support : True              |                                                         |
     | e88213ca-66e6-4ae1-ba1b-d9d2c65bae12 | dhss_false                        | public     | -          | driver_handles_share_servers : False | snapshot_support : True                    | None                                                    |
     |                                      |                                   |            |            |                                      | create_share_from_snapshot_support : True  |                                                         |
     |                                      |                                   |            |            |                                      | revert_to_snapshot_support : True          |                                                         |
     |                                      |                                   |            |            |                                      | mount_snapshot_support : True              |                                                         |
     +--------------------------------------+-----------------------------------+------------+------------+--------------------------------------+--------------------------------------------+---------------------------------------------------------+

Share networks
--------------

* Create a share network.

  .. code-block:: console

     $ manila share-network-create \
         --name mysharenetwork \
         --description "My Manila network" \
         --neutron-net-id 23da40b4-0d5e-468c-8ac9-3766e9ceaacd \
         --neutron-subnet-id 4568bc9b-42fe-45ac-a49b-469e8276223c
     +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
     | Property              | Value                                                                                                                                                                                                                                                                                                                                                                             |
     +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
     | id                    | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                                                                                                                                                                                                                                                                                                                              |
     | name                  | mysharenetwork                                                                                                                                                                                                                                                                                                                                                                    |
     | project_id            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                                                                                                                                                                                                                                                                                                                                  |
     | created_at            | 2020-08-07T04:47:53.000000                                                                                                                                                                                                                                                                                                                                                        |
     | updated_at            | None                                                                                                                                                                                                                                                                                                                                                                              |
     | description           | My Manila network                                                                                                                                                                                                                                                                                                                                                                 |
     | share_network_subnets | [{'id': '187dcd27-8478-45c1-bd5e-5423cafd15ae', 'availability_zone': None, 'created_at': '2020-08-07T04:47:53.000000', 'updated_at': None, 'segmentation_id': None, 'neutron_net_id': '23da40b4-0d5e-468c-8ac9-3766e9ceaacd', 'neutron_subnet_id': '4568bc9b-42fe-45ac-a49b-469e8276223c', 'ip_version': None, 'cidr': None, 'network_type': None, 'mtu': None, 'gateway': None}] |
     +-----------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

  .. note::

     This Manila API does not validate the subnet information you supply right
     away. The validation is performed when creating a share with the share
     network. This is why, you do not see some subnet information populated on
     the share network resource until at least one share is created with it.

* List share networks.

  .. code-block:: console

     $ manila share-network-list
     +--------------------------------------+----------------+
     | id                                   | name           |
     +--------------------------------------+----------------+
     | c4bfdd5e-7502-4a65-8876-0ce8b9914a64 | mysharenetwork |
     +--------------------------------------+----------------+

Create a share
--------------

* Create a share

  .. note::

     If you use a share type that has the extra specification
     ``driver_handles_share_servers=False``,
     you cannot use a share network to create your shares.

  .. code-block:: console

     $ manila create NFS 1 \
         --name myshare \
         --description "My Manila share" \
         --share-network mysharenetwork \
         --share-type dhss_true
     +---------------------------------------+--------------------------------------+
     | Property                              | Value                                |
     +---------------------------------------+--------------------------------------+
     | id                                    | 83b0772b-00ad-4e45-8fad-106b9d4f1719 |
     | size                                  | 1                                    |
     | availability_zone                     | None                                 |
     | created_at                            | 2020-08-07T05:24:14.000000           |
     | status                                | creating                             |
     | name                                  | myshare                              |
     | description                           | My Manila share                      |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b     |
     | snapshot_id                           | None                                 |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64 |
     | share_proto                           | NFS                                  |
     | metadata                              | {}                                   |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172 |
     | is_public                             | False                                |
     | snapshot_support                      | True                                 |
     | task_state                            | None                                 |
     | share_type_name                       | dhss_true                            |
     | access_rules_status                   | active                               |
     | replication_type                      | None                                 |
     | has_replicas                          | False                                |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21     |
     | create_share_from_snapshot_support    | True                                 |
     | revert_to_snapshot_support            | True                                 |
     | share_group_id                        | None                                 |
     | source_share_group_snapshot_member_id | None                                 |
     | mount_snapshot_support                | True                                 |
     | progress                              | None                                 |
     +---------------------------------------+--------------------------------------+

* Show a share.

  .. code-block:: console

     $ manila show myshare
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | Property                              | Value                                                                                                                |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | id                                    | 83b0772b-00ad-4e45-8fad-106b9d4f1719                                                                                 |
     | size                                  | 1                                                                                                                    |
     | availability_zone                     | nova                                                                                                                 |
     | created_at                            | 2020-08-07T05:24:14.000000                                                                                           |
     | status                                | available                                                                                                            |
     | name                                  | myshare                                                                                                              |
     | description                           | My Manila share                                                                                                      |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                                                                     |
     | snapshot_id                           | None                                                                                                                 |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                                                                 |
     | share_proto                           | NFS                                                                                                                  |
     | metadata                              | {}                                                                                                                   |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172                                                                                 |
     | is_public                             | False                                                                                                                |
     | snapshot_support                      | True                                                                                                                 |
     | task_state                            | None                                                                                                                 |
     | share_type_name                       | dhss_true                                                                                                            |
     | access_rules_status                   | active                                                                                                               |
     | replication_type                      | None                                                                                                                 |
     | has_replicas                          | False                                                                                                                |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21                                                                                     |
     | create_share_from_snapshot_support    | True                                                                                                                 |
     | revert_to_snapshot_support            | True                                                                                                                 |
     | share_group_id                        | None                                                                                                                 |
     | source_share_group_snapshot_member_id | None                                                                                                                 |
     | mount_snapshot_support                | True                                                                                                                 |
     | progress                              | 100%                                                                                                                 |
     | export_locations                      |                                                                                                                      |
     |                                       | id = 908e5a28-c5ea-4627-b17c-1cfeb894ccd1                                                                            |
     |                                       | path = 10.0.0.11:/sharevolumes_10034/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = True                                                                                                     |
     |                                       | id = 395244a1-8aa9-44af-9fda-f7d6036ce2b9                                                                            |
     |                                       | path = 10.0.0.10:/sharevolumes_10034/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = False                                                                                                    |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+

* List shares.

  .. code-block:: console

     $ manila list
     +--------------------------------------+--------------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | ID                                   | Name               | Size | Share Proto | Status    | Is Public | Share Type Name | Host | Availability Zone |
     +--------------------------------------+--------------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | 83b0772b-00ad-4e45-8fad-106b9d4f1719 | myshare            | 1    | NFS         | available | False     | dhss_true       |      | nova              |
     +--------------------------------------+--------------------+------+-------------+-----------+-----------+-----------------+------+-------------------+

* List share export locations.

  .. code-block:: console

     $ manila share-export-location-list myshare
     +--------------------------------------+---------------------------------------------------------------------------------------------------------------+-----------+
     | ID                                   | Path                                                                                                          | Preferred |
     +--------------------------------------+---------------------------------------------------------------------------------------------------------------+-----------+
     | 395244a1-8aa9-44af-9fda-f7d6036ce2b9 | 10.0.0.10:/sharevolumes_10034/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd | False     |
     | 908e5a28-c5ea-4627-b17c-1cfeb894ccd1 | 10.0.0.11:/sharevolumes_10034/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd | True      |
     +--------------------------------------+---------------------------------------------------------------------------------------------------------------+-----------+

* Create a share using scheduler hints to specify the host.

  With scheduler hints, you can optionally specify the affinity and anti-affinity rules in relation to other shares.
  The scheduler will enforce these rules when determining where to create the share.
  Possible keys are ``same_host`` and ``different_host``, and the value must be the share name or id.

  .. code-block:: console

     $ manila create NFS 1 \
         --name myshare2 \
         --description "My Manila share - Different Host" \
         --share-network mysharenetwork \
         --share-type dhss_true \
         --scheduler-hints different_host=myshare

     +---------------------------------------+-----------------------------------------------------------------------+
     | Property                              | Value                                                                 |
     +---------------------------------------+-----------------------------------------------------------------------+
     | id                                    | 40de4f4c-4588-4d9c-844b-f74d8951053a                                  |
     | size                                  | 1                                                                     |
     | availability_zone                     | None                                                                  |
     | created_at                            | 2020-08-07T05:24:14.000000                                            |
     | status                                | creating                                                              |
     | name                                  | myshare2                                                              |
     | description                           | My Manila share - Different Host                                      |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                      |
     | snapshot_id                           | None                                                                  |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                  |
     | share_proto                           | NFS                                                                   |
     | metadata                              | {'__affinity_different_host': '83b0772b-00ad-4e45-8fad-106b9d4f1719'} |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172                                  |
     | is_public                             | False                                                                 |
     | snapshot_support                      | True                                                                  |
     | task_state                            | None                                                                  |
     | share_type_name                       | dhss_true                                                             |
     | access_rules_status                   | active                                                                |
     | replication_type                      | None                                                                  |
     | has_replicas                          | False                                                                 |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21                                      |
     | create_share_from_snapshot_support    | True                                                                  |
     | revert_to_snapshot_support            | True                                                                  |
     | share_group_id                        | None                                                                  |
     | source_share_group_snapshot_member_id | None                                                                  |
     | mount_snapshot_support                | True                                                                  |
     | progress                              | None                                                                  |
     +---------------------------------------+-----------------------------------------------------------------------+

   Share is created in a different host.

   .. code-block:: console

     $ manila list
     +--------------------------------------+-----------+------+-------------+-----------+-----------+-----------------+-----------------------------+-------------------+
     | ID                                   | Name      | Size | Share Proto | Status    | Is Public | Share Type Name | Host                        | Availability Zone |
     +--------------------------------------+-----------+------+-------------+-----------+-----------+-----------------+-----------------------------+-------------------+
     | 83b0772b-00ad-4e45-8fad-106b9d4f1719 | myshare   | 1    | NFS         | available | False     | default         | nosb-devstack@london#LONDON | nova              |
     | 40de4f4c-4588-4d9c-844b-f74d8951053a | myshare2  | 1    | NFS         | available | False     | default         | nosb-devstack@lisboa#LISBOA | nova              |
     +--------------------------------------+-----------+------+-------------+-----------+-----------+-----------------+-----------------------------+-------------------+

* Create a share using `mount_point_name`.

  When `mount_point_name_support` is enabled by your administrator, you
  can specify a custom mount point name during share creation. This name
  will be used in conjunction with the prefix set by the administrator
  to form the share's export location.

  The general workflow for using `mount_point_name`:

  - ``Creating a new share``: Specify a custom `mount_point_name` using the
    `--mount-point-name` flag. The `mount_point_name` should not exceed 255
    characters in length.

  .. code-block:: bash

     openstack share create NFS 1 --share-type gold_provisioning_prefix \
     --name MyShare --mount-point-name mount_abc1 \
     --share-network 19d78275-55cb-4684-81f2-ec9c07701563

    +---------------------------------------+--------------------------------------+
    | Field                                 | Value                                |
    +=======================================+======================================+
    | access_rules_status                   | active                               |
    +---------------------------------------+--------------------------------------+
    | availability_zone                     | None                                 |
    +---------------------------------------+--------------------------------------+
    | create_share_from_snapshot_support    | False                                |
    +---------------------------------------+--------------------------------------+
    | created_at                            | 2024-03-20T20:32:50.819345           |
    +---------------------------------------+--------------------------------------+
    | description                           | None                                 |
    +---------------------------------------+--------------------------------------+
    | has_replicas                          | False                                |
    +---------------------------------------+--------------------------------------+
    | host                                  |                                      |
    +---------------------------------------+--------------------------------------+
    | id                                    | 138a6884-7a9b-4d9a-9ac1-f565701a4b83 |
    +---------------------------------------+--------------------------------------+
    | is_public                             | False                                |
    +---------------------------------------+--------------------------------------+
    | is_soft_deleted                       | False                                |
    +---------------------------------------+--------------------------------------+
    | metadata                              | {}                                   |
    +---------------------------------------+--------------------------------------+
    | mount_snapshot_support                | False                                |
    +---------------------------------------+--------------------------------------+
    | name                                  | MyShare                              |
    +---------------------------------------+--------------------------------------+
    | progress                              | None                                 |
    +---------------------------------------+--------------------------------------+
    | project_id                            | 44754d5c4aea4c8c8d619bb6b4ebeb17     |
    +---------------------------------------+--------------------------------------+
    | replication_type                      | None                                 |
    +---------------------------------------+--------------------------------------+
    | revert_to_snapshot_support            | False                                |
    +---------------------------------------+--------------------------------------+
    | scheduled_to_be_deleted_at            | None                                 |
    +---------------------------------------+--------------------------------------+
    | share_group_id                        | None                                 |
    +---------------------------------------+--------------------------------------+
    | share_network_id                      | 19d78275-55cb-4684-81f2-ec9c07701563 |
    +---------------------------------------+--------------------------------------+
    | share_proto                           | NFS                                  |
    +---------------------------------------+--------------------------------------+
    | share_server_id                       | None                                 |
    +---------------------------------------+--------------------------------------+
    | share_type                            | ee1995d8-6827-4711-a58d-38ee00f24a75 |
    +---------------------------------------+--------------------------------------+
    | share_type_name                       | gold_provisioning_prefix             |
    +---------------------------------------+--------------------------------------+
    | size                                  | 1                                    |
    +---------------------------------------+--------------------------------------+
    | snapshot_id                           | None                                 |
    +---------------------------------------+--------------------------------------+
    | snapshot_support                      | False                                |
    +---------------------------------------+--------------------------------------+
    | source_backup_id                      | None                                 |
    +---------------------------------------+--------------------------------------+
    | source_share_group_snapshot_member_id | None                                 |
    +---------------------------------------+--------------------------------------+
    | status                                | creating                             |
    +---------------------------------------+--------------------------------------+
    | task_state                            | None                                 |
    +---------------------------------------+--------------------------------------+
    | user_id                               | fbdba3d017b2484f9773033e3fc0c6ae     |
    +---------------------------------------+--------------------------------------+
    | volume_type                           | gold_provisioning_prefix             |
    +---------------------------------------+--------------------------------------+

* To view the details of a share created with custom mount_point_name.

  .. code-block:: console

     $ openstack share show 138a6884-7a9b-4d9a-9ac1-f565701a4b83

    +---------------------------------------+-------------------------------------------------------------------------+
    | Field                                 | Value                                                                   |
    +---------------------------------------+-------------------------------------------------------------------------+
    | access_rules_status                   | active                                                                  |
    | availability_zone                     | nova                                                                    |
    | create_share_from_snapshot_support    | False                                                                   |
    | created_at                            | 2024-03-20T20:32:50.819345                                              |
    | description                           | None                                                                    |
    | export_locations                      |                                                                         |
    |                                       | id = 1f5d8a51-965e-4062-a1e1-03ca146ad277                               |
    |                                       | path = <ip>:/gold_mount_abc1                                            |
    |                                       | preferred = True                                                        |
    |                                       | share_instance_id = 62a4d622-a3c8-4915-adca-54a7fe5789bf                |
    |                                       | is_admin_only = False                                                   |
    |                                       | id = ea7c936a-d94b-47bd-8a35-4b2f1f7b5e5a                               |
    |                                       | path = <ip>:/gold_mount_abc1                                            |
    |                                       | preferred = False                                                       |
    |                                       | share_instance_id = 62a4d622-a3c8-4915-adca-54a7fe5789bf                |
    |                                       | is_admin_only = False                                                   |
    | has_replicas                          | False                                                                   |
    | host                                  | host@share_server_dhss_true#AstraInfra                                  |
    | id                                    | 138a6884-7a9b-4d9a-9ac1-f565701a4b83                                    |
    | is_public                             | False                                                                   |
    | is_soft_deleted                       | False                                                                   |
    | mount_snapshot_support                | False                                                                   |
    | name                                  | MyShare                                                                 |
    | progress                              | 100%                                                                    |
    | project_id                            | 44754d5c4aea4c8c8d619bb6b4ebeb17                                        |
    | properties                            |                                                                         |
    | replication_type                      | None                                                                    |
    | revert_to_snapshot_support            | False                                                                   |
    | scheduled_to_be_deleted_at            | None                                                                    |
    | share_group_id                        | None                                                                    |
    | share_network_id                      | 19d78275-55cb-4684-81f2-ec9c07701563                                    |
    | share_proto                           | NFS                                                                     |
    +---------------------------------------+-------------------------------------------------------------------------+


* Create a share using encryption key reference.

  User can create share using their own encryption key. The key must be stored
  in key-manager (Openstack Barbican) service. First create share type and
  specify extra-spec ``encryption_support``. It can have value ``share`` or
  ``share_server`` based on support by backend storage driver. Then use
  `--encryption-key-ref` option in share create command. Users can use
  encryption key reference or UUID of key reference here.

  .. code-block:: console

     $ openstack share create NFS 1 \
         --name myshare3 \
         --description "My Manila share - Encrypted" \
         --share-network mysharenetwork \
         --share-type encrypted_share_type \
         --encryption-key-ref 86babe9b-7277-4c3a-a081-6eb3eac9231d

     +---------------------------------------+-----------------------------------------------------------------------+
     | Property                              | Value                                                                 |
     +---------------------------------------+-----------------------------------------------------------------------+
     | id                                    | 40de4f4c-4588-4d9c-844b-f74d8951053a                                  |
     | size                                  | 1                                                                     |
     | availability_zone                     | None                                                                  |
     | created_at                            | 2020-08-07T05:24:14.000000                                            |
     | status                                | creating                                                              |
     | name                                  | myshare3                                                              |
     | description                           | My Manila share - Encrypted                                           |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                      |
     | snapshot_id                           | None                                                                  |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                  |
     | share_proto                           | NFS                                                                   |
     | metadata                              | {}                                                                    |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172                                  |
     | is_public                             | False                                                                 |
     | snapshot_support                      | True                                                                  |
     | task_state                            | None                                                                  |
     | share_type_name                       | encrypted_share_type                                                  |
     | access_rules_status                   | active                                                                |
     | replication_type                      | None                                                                  |
     | has_replicas                          | False                                                                 |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21                                      |
     | create_share_from_snapshot_support    | True                                                                  |
     | revert_to_snapshot_support            | True                                                                  |
     | share_group_id                        | None                                                                  |
     | encryption_key_ref                    | 86babe9b-7277-4c3a-a081-6eb3eac9231d                                  |
     | source_share_group_snapshot_member_id | None                                                                  |
     | mount_snapshot_support                | True                                                                  |
     | progress                              | None                                                                  |
     +---------------------------------------+-----------------------------------------------------------------------+


Grant and revoke share access
-----------------------------

.. tip::

  Starting from the 2023.2 (Bobcat) release, in case you want to restrict the
  visibility of the sensitive fields (``access_to`` and ``access_key``), or
  avoid the access rule being deleted by other users, you can specify
  ``--lock-visibility`` and ``--lock-deletion`` in the Manila OpenStack command
  for creating access rules. A reason (``--lock-reason``) can also be provided.
  Only the user that placed the lock, system administrators and services will
  be able to manipulate such access rules. In case the deletion of the access
  rule was locked, Manila will also place an additional lock on the share, to
  ensure it will not be deleted and cause disconnections.

Allow read-write access
~~~~~~~~~~~~~~~~~~~~~~~

* Allow access.

  .. code-block:: console

     $ manila access-allow myshare ip 10.0.0.0/24 --metadata key1=value1
     +--------------+--------------------------------------+
     | Property     | Value                                |
     +--------------+--------------------------------------+
     | id           | e30bde96-9217-4f90-afdc-27c092af1c77 |
     | share_id     | 83b0772b-00ad-4e45-8fad-106b9d4f1719 |
     | access_level | rw                                   |
     | access_to    | 10.0.0.0/24                          |
     | access_type  | ip                                   |
     | state        | queued_to_apply                      |
     | access_key   | None                                 |
     | created_at   | 2020-08-07T05:27:27.000000           |
     | updated_at   | None                                 |
     | metadata     | {'key1': 'value1'}                   |
     +--------------+--------------------------------------+

  .. note::
      Since API version 2.38, access rules of type IP supports IPv6 addresses
      and subnets in CIDR notation.

  .. note::
      Since API version 2.45, metadata can be added, removed and updated for
      share access rules in a form of key=value pairs. Metadata can help you
      identify and filter access rules.

* List access.

  .. code-block:: console

     $ manila access-list myshare
     +--------------------------------------+-------------+-------------+--------------+--------+------------+----------------------------+------------+
     | id                                   | access_type | access_to   | access_level | state  | access_key | created_at                 | updated_at |
     +--------------------------------------+-------------+-------------+--------------+--------+------------+----------------------------+------------+
     | e30bde96-9217-4f90-afdc-27c092af1c77 | ip          | 10.0.0.0/24 | rw           | active | None       | 2020-08-07T05:27:27.000000 | None       |
     +--------------------------------------+-------------+-------------+--------------+--------+------------+----------------------------+------------+

  An access rule is created.

Allow read-only access
~~~~~~~~~~~~~~~~~~~~~~

* Allow access.

  .. code-block:: console

     $ manila access-allow myshare ip fd31:7ee0:3de4:a41b::/64 --access-level ro
     +--------------+--------------------------------------+
     | Property     | Value                                |
     +--------------+--------------------------------------+
     | id           | 45b0a030-306a-4305-9e2a-36aeffb2d5b7 |
     | share_id     | 83b0772b-00ad-4e45-8fad-106b9d4f1719 |
     | access_level | ro                                   |
     | access_to    | fd31:7ee0:3de4:a41b::/64             |
     | access_type  | ip                                   |
     | state        | queued_to_apply                      |
     | access_key   | None                                 |
     | created_at   | 2020-08-07T05:28:35.000000           |
     | updated_at   | None                                 |
     | metadata     | {}                                   |
     +--------------+--------------------------------------+

* List access.

  .. code-block:: console

     $ manila access-list myshare
     +--------------------------------------+-------------+----------------------------+--------------+--------+------------+----------------------------+------------+
     | id                                   | access_type | access_to                  | access_level | state  | access_key | created_at                 | updated_at |
     +--------------------------------------+-------------+----------------------------+--------------+--------+------------+----------------------------+------------+
     | 45b0a030-306a-4305-9e2a-36aeffb2d5b7 | ip          | fd31:7ee0:3de4:a41b::/64   | ro           | active | None       | 2020-08-07T05:28:35.000000 | None       |
     | e30bde96-9217-4f90-afdc-27c092af1c77 | ip          | 10.0.0.0/24                | rw           | active | None       | 2020-08-07T05:27:27.000000 | None       |
     +--------------------------------------+-------------+----------------------------+--------------+--------+------------+----------------------------+------------+

  Another access rule is created.

.. note::

  In case one or more access rules had its visibility locked, you might not be
  able to see the content of the fields containing sensitive information
  (``access_to`` and ``access_key``).

Update access rules metadata
----------------------------

#. Add a new metadata.

   .. code-block:: console

      $ manila access-metadata 0c8470ca-0d77-490c-9e71-29e1f453bf97 set key2=value2
      $ manila access-show 0c8470ca-0d77-490c-9e71-29e1f453bf97
      +--------------+--------------------------------------+
      | Property     | Value                                |
      +--------------+--------------------------------------+
      | id           | 0c8470ca-0d77-490c-9e71-29e1f453bf97 |
      | share_id     | 8d8b854b-ec32-43f1-acc0-1b2efa7c3400 |
      | access_level | rw                                   |
      | access_to    | 10.0.0.0/24                          |
      | access_type  | ip                                   |
      | state        | active                               |
      | access_key   | None                                 |
      | created_at   | 2016-03-24T14:51:36.000000           |
      | updated_at   | None                                 |
      | metadata     | {'key1': 'value1', 'key2': 'value2'} |
      +--------------+--------------------------------------+

#. Remove a metadata key value.

   .. code-block:: console

      $ manila access-metadata 0c8470ca-0d77-490c-9e71-29e1f453bf97 unset key
      $ manila access-show 0c8470ca-0d77-490c-9e71-29e1f453bf97
      +--------------+--------------------------------------+
      | Property     | Value                                |
      +--------------+--------------------------------------+
      | id           | 0c8470ca-0d77-490c-9e71-29e1f453bf97 |
      | share_id     | 8d8b854b-ec32-43f1-acc0-1b2efa7c3400 |
      | access_level | rw                                   |
      | access_to    | 10.0.0.0/24                          |
      | access_type  | ip                                   |
      | state        | active                               |
      | access_key   | None                                 |
      | created_at   | 2016-03-24T14:51:36.000000           |
      | updated_at   | None                                 |
      | metadata     | {'key2': 'value2'}                   |
      +--------------+--------------------------------------+

Deny access
-----------

* Deny access.

  .. code-block:: console

     $ manila access-deny myshare 45b0a030-306a-4305-9e2a-36aeffb2d5b7
     $ manila access-deny myshare e30bde96-9217-4f90-afdc-27c092af1c77

.. note::

  Starting from the 2023.2 (Bobcat) release, it is possible to prevent the
  deletion of an access rule. In case you have placed a deletion lock during
  the access rule creation, the ``--unrestrict`` argument from the Manila's
  OpenStack Client must be used in the request to revoke the access.

* List access.

  .. code-block:: console

     $ manila access-list myshare
     +----+-------------+-----------+--------------+-------+------------+------------+------------+
     | id | access_type | access_to | access_level | state | access_key | created_at | updated_at |
     +----+-------------+-----------+--------------+-------+------------+------------+------------+
     +----+-------------+-----------+--------------+-------+------------+------------+------------+

  The access rules are removed.

Create snapshot
---------------

* Create a snapshot.

  .. note::

     To create a snapshot, the share type of the share must contain the
     capability extra-spec ``snapshot_support=True``.

  .. code-block:: console

     $ openstack share snapshot create --name mysnap --description "My Manila snapshot" myshare
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | id                | 286edbe1-a69e-40e7-ad50-61287570df55 |
    | share_id          | bf7ffbb7-73a5-44fe-a93e-73cbd5a9197d |
    | share_size        | 1                                    |
    | created_at        | 2025-03-08T00:06:32.123637           |
    | status            | creating                             |
    | name              | mysnap                               |
    | description       | My Manila snapshot                   |
    | size              | 1                                    |
    | share_proto       | NFS                                  |
    | provider_location | None                                 |
    | user_id           | 64e1409650ee4e94a8e78df24da86091     |
    | project_id        | dd43995fee324b24b79adab2542d74e9     |
    | metadata          | {}                                   |
    +-------------------+--------------------------------------+

* List snapshots.

  .. code-block:: console

     $ openstack share snapshot list
    +--------------------------------------+--------+
    | ID                                   | Name   |
    +--------------------------------------+--------+
    | 7861eed0-8634-41e0-a57e-a1d87ad48a1b | mysnap |
    +--------------------------------------+--------+


Mount a snapshot
----------------

* Allow access to the snapshot.

  .. note::

     To mount a snapshot, the share type of the parent share must contain the
     capability extra-spec ``mount_snapshot_support=True``.

  .. code-block:: console

     $ openstack share snapshot access create mysnap ip 192.168.1.0/24
    +-------------+--------------------------------------+
    | Field       | Value                                |
    +-------------+--------------------------------------+
    | id          | 89e36a97-19d8-430c-b920-6d930ea27464 |
    | access_type | ip                                   |
    | access_to   | 192.168.1.0/24                       |
    | state       | queued_to_apply                      |
    +-------------+--------------------------------------+

* List snapshot access.

  .. code-block:: console

     $ openstack share snapshot access list mysnap
    +--------------------------------------+-------------+----------------+--------+
    | ID                                   | Access Type | Access To      | State  |
    +--------------------------------------+-------------+----------------+--------+
    | 89e36a97-19d8-430c-b920-6d930ea27464 | ip          | 192.168.1.0/24 | active |
    +--------------------------------------+-------------+----------------+--------+

Then proceed to mounting the snapshot on the clients whose access was created.

* Delete snapshot access rule.

  .. code-block:: console

     $ openstack share snapshot access delete mysnap 89e36a97-19d8-430c-b920-6d930ea27464


Create share from snapshot
--------------------------

* Create a share from a snapshot.

  .. note::

     To create a share from a snapshot, the share type of the parent share
     must contain the capability extra-spec
     ``create_share_from_snapshot_support=True``.

  .. code-block:: console

     $ manila create NFS 1 \
         --snapshot-id 8a18aa77-7500-4e56-be8f-6081146f47f1 \
         --share-network mysharenetwork \
         --name mysharefromsnap
     +---------------------------------------+--------------------------------------+
     | Property                              | Value                                |
     +---------------------------------------+--------------------------------------+
     | id                                    | 2a9336ea-3afc-4443-80bb-398f4bdb3a93 |
     | size                                  | 1                                    |
     | availability_zone                     | nova                                 |
     | created_at                            | 2020-08-07T05:34:12.000000           |
     | status                                | creating                             |
     | name                                  | mysharefromsnap                      |
     | description                           | None                                 |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b     |
     | snapshot_id                           | 8a18aa77-7500-4e56-be8f-6081146f47f1 |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64 |
     | share_proto                           | NFS                                  |
     | metadata                              | {}                                   |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172 |
     | is_public                             | False                                |
     | snapshot_support                      | True                                 |
     | task_state                            | None                                 |
     | share_type_name                       | dhss_true                            |
     | access_rules_status                   | active                               |
     | replication_type                      | None                                 |
     | has_replicas                          | False                                |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21     |
     | create_share_from_snapshot_support    | True                                 |
     | revert_to_snapshot_support            | True                                 |
     | share_group_id                        | None                                 |
     | source_share_group_snapshot_member_id | None                                 |
     | mount_snapshot_support                | True                                 |
     | progress                              | None                                 |
     +---------------------------------------+--------------------------------------+

* List shares.

  .. code-block:: console

     $ openstack share list
    +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+-------------------------------------------+-------------------+
    | ID                                   | Name    | Size | Share Proto | Status    | Is Public | Share Type Name | Host                                      | Availability Zone |
    +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+-------------------------------------------+-------------------+
    | bf7ffbb7-73a5-44fe-a93e-73cbd5a9197d | myshare |    1 | NFS         | available | False     | default         | oid-na-scale-1@bogota#fake_pool_for_DELTA | manila-zone-3     |
    +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+-------------------------------------------+-------------------+

* Show the share created from snapshot.

  .. code-block:: console

     $ manila show mysharefromsnap
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | Property                              | Value                                                                                                                |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | id                                    | 2a9336ea-3afc-4443-80bb-398f4bdb3a93                                                                                 |
     | size                                  | 1                                                                                                                    |
     | availability_zone                     | nova                                                                                                                 |
     | created_at                            | 2020-08-07T05:34:12.000000                                                                                           |
     | status                                | available                                                                                                            |
     | name                                  | mysharefromsnap                                                                                                      |
     | description                           | None                                                                                                                 |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                                                                     |
     | snapshot_id                           | 8a18aa77-7500-4e56-be8f-6081146f47f1                                                                                 |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                                                                 |
     | share_proto                           | NFS                                                                                                                  |
     | metadata                              | {}                                                                                                                   |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172                                                                                 |
     | is_public                             | False                                                                                                                |
     | snapshot_support                      | True                                                                                                                 |
     | task_state                            | None                                                                                                                 |
     | share_type_name                       | dhss_true                                                                                                            |
     | access_rules_status                   | active                                                                                                               |
     | replication_type                      | None                                                                                                                 |
     | has_replicas                          | False                                                                                                                |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21                                                                                     |
     | create_share_from_snapshot_support    | True                                                                                                                 |
     | revert_to_snapshot_support            | True                                                                                                                 |
     | share_group_id                        | None                                                                                                                 |
     | source_share_group_snapshot_member_id | None                                                                                                                 |
     | mount_snapshot_support                | True                                                                                                                 |
     | progress                              | 100%                                                                                                                 |
     | export_locations                      |                                                                                                                      |
     |                                       | id = 7928b361-cada-4505-a62e-4cefb1cf6fc5                                                                            |
     |                                       | path = 10.0.0.11:/path/to/fake/share/share_2a9336ea_3afc_4443_80bb_398f4bdb3a93_97de2abe_d114_49a9_9d01_ce5e71337e48 |
     |                                       | preferred = True                                                                                                     |
     |                                       | id = e48d19ba-dee5-4492-b156-5181530955be                                                                            |
     |                                       | path = 10.0.0.10:/path/to/fake/share/share_2a9336ea_3afc_4443_80bb_398f4bdb3a93_97de2abe_d114_49a9_9d01_ce5e71337e48 |
     |                                       | preferred = False                                                                                                    |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+

Delete share
------------

* Delete a share.

  .. code-block:: console

     $ manila delete mysharefromsnap

* List shares.

  .. code-block:: console

     $ manila list
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+-----------------------------+-------------------+
     | ID                                   | Name            | Size | Share Proto | Status    | Is Public | Share Type Name | Host                        | Availability Zone |
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+-----------------------------+-------------------+
     | 83b0772b-00ad-4e45-8fad-106b9d4f1719 | myshare         | 1    | NFS         | available | False     | default         | nosb-devstack@london#LONDON | nova              |
     | 2a9336ea-3afc-4443-80bb-398f4bdb3a93 | mysharefromsnap | 1    | NFS         | deleting  | False     | default         | nosb-devstack@london#LONDON | nova              |
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+-----------------------------+-------------------+

  The share is being deleted.

Delete snapshot
---------------

* Delete a snapshot.

  .. code-block:: console

     $ openstack share snapshot delete mysnapshot

* List snapshots after deleting.

  .. code-block:: console

     $ openstack share snapshot list


  The snapshot is deleted.

Extend share
------------

* Extend share.

  .. code-block:: console

     $ manila extend myshare 2

* Show the share while it is being extended.

  .. code-block:: console

     $ manila show myshare
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | Property                              | Value                                                                                                                |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | id                                    | 83b0772b-00ad-4e45-8fad-106b9d4f1719                                                                                 |
     | size                                  | 1                                                                                                                    |
     | availability_zone                     | nova                                                                                                                 |
     | created_at                            | 2020-08-07T05:24:14.000000                                                                                           |
     | status                                | extending                                                                                                            |
     | name                                  | myshare                                                                                                              |
     | description                           | My Manila share                                                                                                      |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                                                                     |
     | snapshot_id                           | None                                                                                                                 |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                                                                 |
     | share_proto                           | NFS                                                                                                                  |
     | metadata                              | {}                                                                                                                   |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172                                                                                 |
     | is_public                             | False                                                                                                                |
     | snapshot_support                      | True                                                                                                                 |
     | task_state                            | None                                                                                                                 |
     | share_type_name                       | dhss_true                                                                                                            |
     | access_rules_status                   | active                                                                                                               |
     | replication_type                      | None                                                                                                                 |
     | has_replicas                          | False                                                                                                                |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21                                                                                     |
     | create_share_from_snapshot_support    | True                                                                                                                 |
     | revert_to_snapshot_support            | True                                                                                                                 |
     | share_group_id                        | None                                                                                                                 |
     | source_share_group_snapshot_member_id | None                                                                                                                 |
     | mount_snapshot_support                | True                                                                                                                 |
     | progress                              | 100%                                                                                                                 |
     | export_locations                      |                                                                                                                      |
     |                                       | id = 908e5a28-c5ea-4627-b17c-1cfeb894ccd1                                                                            |
     |                                       | path = 10.0.0.11:/path/to/fake/share/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = True                                                                                                     |
     |                                       | id = 395244a1-8aa9-44af-9fda-f7d6036ce2b9                                                                            |
     |                                       | path = 10.0.0.10:/path/to/fake/share/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = False                                                                                                    |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+

* Show the share after it is extended.

  .. code-block:: console

     $ manila show myshare
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | Property                              | Value                                                                                                                |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | id                                    | 83b0772b-00ad-4e45-8fad-106b9d4f1719                                                                                 |
     | size                                  | 2                                                                                                                    |
     | availability_zone                     | nova                                                                                                                 |
     | created_at                            | 2020-08-07T05:24:14.000000                                                                                           |
     | status                                | available                                                                                                            |
     | name                                  | myshare                                                                                                              |
     | description                           | My Manila share                                                                                                      |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                                                                     |
     | snapshot_id                           | None                                                                                                                 |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                                                                 |
     | share_proto                           | NFS                                                                                                                  |
     | metadata                              | {}                                                                                                                   |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172                                                                                 |
     | is_public                             | False                                                                                                                |
     | snapshot_support                      | True                                                                                                                 |
     | task_state                            | None                                                                                                                 |
     | share_type_name                       | dhss_true                                                                                                            |
     | access_rules_status                   | active                                                                                                               |
     | replication_type                      | None                                                                                                                 |
     | has_replicas                          | False                                                                                                                |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21                                                                                     |
     | create_share_from_snapshot_support    | True                                                                                                                 |
     | revert_to_snapshot_support            | True                                                                                                                 |
     | share_group_id                        | None                                                                                                                 |
     | source_share_group_snapshot_member_id | None                                                                                                                 |
     | mount_snapshot_support                | True                                                                                                                 |
     | progress                              | 100%                                                                                                                 |
     | export_locations                      |                                                                                                                      |
     |                                       | id = 908e5a28-c5ea-4627-b17c-1cfeb894ccd1                                                                            |
     |                                       | path = 10.0.0.11:/path/to/fake/share/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = True                                                                                                     |
     |                                       | id = 395244a1-8aa9-44af-9fda-f7d6036ce2b9                                                                            |
     |                                       | path = 10.0.0.10:/path/to/fake/share/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = False                                                                                                    |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+

Shrink share
------------

* Shrink a share.

  .. code-block:: console

     $ manila shrink myshare 1

* Show the share while it is being shrunk.

  .. code-block:: console

     $ manila show myshare
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | Property                              | Value                                                                                                                |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | id                                    | 83b0772b-00ad-4e45-8fad-106b9d4f1719                                                                                 |
     | size                                  | 2                                                                                                                    |
     | availability_zone                     | nova                                                                                                                 |
     | created_at                            | 2020-08-07T05:24:14.000000                                                                                           |
     | status                                | shrinking                                                                                                            |
     | name                                  | myshare                                                                                                              |
     | description                           | My Manila share                                                                                                      |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                                                                     |
     | snapshot_id                           | None                                                                                                                 |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                                                                 |
     | share_proto                           | NFS                                                                                                                  |
     | metadata                              | {}                                                                                                                   |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172                                                                                 |
     | is_public                             | False                                                                                                                |
     | snapshot_support                      | True                                                                                                                 |
     | task_state                            | None                                                                                                                 |
     | share_type_name                       | dhss_true                                                                                                            |
     | access_rules_status                   | active                                                                                                               |
     | replication_type                      | None                                                                                                                 |
     | has_replicas                          | False                                                                                                                |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21                                                                                     |
     | create_share_from_snapshot_support    | True                                                                                                                 |
     | revert_to_snapshot_support            | True                                                                                                                 |
     | share_group_id                        | None                                                                                                                 |
     | source_share_group_snapshot_member_id | None                                                                                                                 |
     | mount_snapshot_support                | True                                                                                                                 |
     | progress                              | 100%                                                                                                                 |
     | export_locations                      |                                                                                                                      |
     |                                       | id = 908e5a28-c5ea-4627-b17c-1cfeb894ccd1                                                                            |
     |                                       | path = 10.0.0.11:/path/to/fake/share/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = True                                                                                                     |
     |                                       | id = 395244a1-8aa9-44af-9fda-f7d6036ce2b9                                                                            |
     |                                       | path = 10.0.0.10:/path/to/fake/share/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = False                                                                                                    |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+

* Show the share after it is being shrunk.

  .. code-block:: console

     $ manila show myshare
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | Property                              | Value                                                                                                                |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+
     | id                                    | 83b0772b-00ad-4e45-8fad-106b9d4f1719                                                                                 |
     | size                                  | 1                                                                                                                    |
     | availability_zone                     | nova                                                                                                                 |
     | created_at                            | 2020-08-07T05:24:14.000000                                                                                           |
     | status                                | available                                                                                                            |
     | name                                  | myshare                                                                                                              |
     | description                           | My Manila share                                                                                                      |
     | project_id                            | d9932a60d9ee4087b6cff9ce6e9b4e3b                                                                                     |
     | snapshot_id                           | None                                                                                                                 |
     | share_network_id                      | c4bfdd5e-7502-4a65-8876-0ce8b9914a64                                                                                 |
     | share_proto                           | NFS                                                                                                                  |
     | metadata                              | {}                                                                                                                   |
     | share_type                            | af7b64ec-cdb3-4a5f-93c9-51672d72e172                                                                                 |
     | is_public                             | False                                                                                                                |
     | snapshot_support                      | True                                                                                                                 |
     | task_state                            | None                                                                                                                 |
     | share_type_name                       | dhss_true                                                                                                            |
     | access_rules_status                   | active                                                                                                               |
     | replication_type                      | None                                                                                                                 |
     | has_replicas                          | False                                                                                                                |
     | user_id                               | 2cebd96a794f431caa06ce5215e0da21                                                                                     |
     | create_share_from_snapshot_support    | True                                                                                                                 |
     | revert_to_snapshot_support            | True                                                                                                                 |
     | share_group_id                        | None                                                                                                                 |
     | source_share_group_snapshot_member_id | None                                                                                                                 |
     | mount_snapshot_support                | True                                                                                                                 |
     | progress                              | 100%                                                                                                                 |
     | export_locations                      |                                                                                                                      |
     |                                       | id = 908e5a28-c5ea-4627-b17c-1cfeb894ccd1                                                                            |
     |                                       | path = 10.0.0.11:/path/to/fake/share/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = True                                                                                                     |
     |                                       | id = 395244a1-8aa9-44af-9fda-f7d6036ce2b9                                                                            |
     |                                       | path = 10.0.0.10:/path/to/fake/share/share_83b0772b_00ad_4e45_8fad_106b9d4f1719_da404d59_4280_4b32_847f_6cfa4f730bbd |
     |                                       | preferred = False                                                                                                    |
     +---------------------------------------+----------------------------------------------------------------------------------------------------------------------+

Share metadata
--------------

* Set metadata items on your share

  .. code-block:: console

     $ manila metadata myshare set purpose='storing financial data for analysis' year_started=2020

* Show share metadata

  .. code-block:: console

     $ manila metadata-show myshare
     +--------------+-------------------------------------+
     | Property     | Value                               |
     +--------------+-------------------------------------+
     | purpose      | storing financial data for analysis |
     | year_started | 2020                                |
     +--------------+-------------------------------------+

* Query share list with metadata

  .. code-block:: console

     $ manila list --metadata year_started=2020
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | ID                                   | Name    | Size | Share Proto | Status    | Is Public | Share Type Name | Host | Availability Zone |
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | 83b0772b-00ad-4e45-8fad-106b9d4f1719 | myshare | 1    | NFS         | available | False     | dhss_true       |      | nova              |
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+

* Unset share metadata

  .. code-block:: console

     $ manila metadata myshare unset year_started

Share revert to snapshot
------------------------

* Share revert to snapshot

  .. note::

   -  To revert a share to its snapshot, the share type of the share must
      contain the capability extra-spec ``revert_to_snapshot_support=True``.
   -  The revert operation can only be performed to the most recent available
      snapshot of the share known to manila. If revert to an earlier snapshot
      is desired, later snapshots must explicitly be deleted.

  .. code-block:: console

     $ manila revert-to-snapshot mysnapshot

Share Transfer
--------------

* Transfer a share to a different project

  .. note::

   -  Share transfer is available for ``driver_handles_share_servers=False``,
      only supports transferring shares that are not created with a share
      network.
   -  Shares that are in transitional states, or possessing replicas, or
      within share groups cannot be transferred.

  .. code-block:: console

     $ manila share-transfer-create myshare --name mytransfer
     +------------------------+--------------------------------------+
     | Property               | Value                                |
     +------------------------+--------------------------------------+
     | id                     | 1c56314e-7e97-455a-bbde-83828db038d4 |
     | created_at             | 2023-05-25T14:37:11.178869           |
     | name                   | mytransfer                           |
     | resource_type          | share                                |
     | resource_id            | 5573c214-ef79-4fb7-83f8-8c01fbe847f7 |
     | source_project_id      | 88b1f2cf8f554edaa8dd92892d1eabf7     |
     | destination_project_id | None                                 |
     | accepted               | False                                |
     | expires_at             | 2023-05-25T14:42:11.176049           |
     | auth_key               | af429e22e0abc31d                     |
     +------------------------+--------------------------------------+

* Accept share transfer

  .. note::

   -  Accept share transfer is performed by a user in a different project.

  .. code-block:: console

     $ manila share-transfer-accept 1c56314e-7e97-455a-bbde-83828db038d4  af429e22e0abc31d

* Delete a transfer

  .. code-block:: console

     $ manila share-transfer-delete 1c56314e-7e97-455a-bbde-83828db038d4

* List transfers

  .. code-block:: console

     $ manila share-transfer-list
     +--------------------------------------+------------+---------------+--------------------------------------+
     | ID                                   | Name       | Resource Type | Resource Id                          |
     +--------------------------------------+------------+---------------+--------------------------------------+
     | 1c56314e-7e97-455a-bbde-83828db038d4 | mytransfer | share         | 5573c214-ef79-4fb7-83f8-8c01fbe847f7 |
     +--------------------------------------+------------+---------------+--------------------------------------+

* Show a share transfer

  .. code-block:: console

     $ manila share-transfer-show 1c56314e-7e97-455a-bbde-83828db038d4
     +------------------------+--------------------------------------+
     | Property               | Value                                |
     +------------------------+--------------------------------------+
     | id                     | 1c56314e-7e97-455a-bbde-83828db038d4 |
     | created_at             | 2023-05-25T14:37:11.178869           |
     | name                   | mytransfer                           |
     | resource_type          | share                                |
     | resource_id            | 5573c214-ef79-4fb7-83f8-8c01fbe847f7 |
     | source_project_id      | 88b1f2cf8f554edaa8dd92892d1eabf7     |
     | destination_project_id | None                                 |
     | accepted               | False                                |
     | expires_at             | 2023-05-25T14:42:11.176049           |
     +------------------------+--------------------------------------+

Snapshot metadata
-----------------

* Set metadata items on your share snapshot during creation

  .. code-block:: console

     $ openstack share snapshot create myshare --name mysnapshot \
        --property key1=value1 --property key2=value2
    +-------------------+--------------------------------------+
    | Field             | Value                                |
    +-------------------+--------------------------------------+
    | created_at        | 2024-03-25T15:39:52.555692           |
    | description       | None                                 |
    | id                | 00a82c82-cb49-414b-a334-c1a1e9b360d5 |
    | metadata          | {'key1': 'value1', 'key2': 'value2'} |
    | name              | mysnapshot                           |
    | project_id        | df63c20d921f48d8802083fdb858fd3e     |
    | provider_location | None                                 |
    | share_id          | 6c4d785b-9034-400b-95de-3d4f06280b31 |
    | share_proto       | NFS                                  |
    | share_size        | 1                                    |
    | size              | 1                                    |
    | status            | creating                             |
    | user_id           | b3369f53dadd40499d797a9a4ee9326b     |
    +-------------------+--------------------------------------+

* Set metadata items on your share snapshot

  .. code-block:: console

     $ openstack share snapshot set mysnapshot --property key1=value


* Query snapshot list with metadata

  .. code-block:: console

     $ openstack share snapshot list --property key1=value1
     +--------------------------------------+------------+
     | ID                                   | Name       |
     +--------------------------------------+------------+
     | 83b0772b-00ad-4e45-8fad-106b9d4f1719 | mysnapshot |
     +--------------------------------------+------------+

* Unset snapshot metadata

  .. code-block:: console

     $ openstack share snapshot unset mysnapshot --property key1


Resource locks
--------------

* Prevent a share from being deleted by creating a ``resource lock``:

  .. code-block:: console

    $ openstack share lock create myshare share
    +-----------------+--------------------------------------+
    | Field           | Value                                |
    +-----------------+--------------------------------------+
    | created_at      | 2023-07-18T05:11:56.626667           |
    | id              | dc7ec691-a505-47d0-b2ec-8eb7fb9270e4 |
    | lock_context    | user                                 |
    | lock_reason     | None                                 |
    | project_id      | db2e72fef7864bbbbf210f22da7f1158     |
    | resource_action | delete                               |
    | resource_id     | 4c0b4d35-4ea8-4811-a1e2-a065c64225a8 |
    | resource_type   | share                                |
    | updated_at      | None                                 |
    | user_id         | 89de351d3b5744b9853ec4829aa0e714     |
    +-----------------+--------------------------------------+

  .. note::

    A ``delete`` (deletion) lock on a share would prevent deletion and other
    actions on a share that are similar to deletion. Similar actions include
    moving a share to the recycle bin (``soft deletion``) or removing a
    share from the Shared File Systems service
    (``unmanage``).



* Get details of a resource lock:

  .. code-block:: console

    $ openstack share lock list --resource myshare --resource-type share
    +--------------------------------------+--------------------------------------+---------------+-----------------+
    | ID                                   | Resource Id                          | Resource Type | Resource Action |
    +--------------------------------------+--------------------------------------+---------------+-----------------+
    | dc7ec691-a505-47d0-b2ec-8eb7fb9270e4 | 4c0b4d35-4ea8-4811-a1e2-a065c64225a8 | share         | delete          |
    +--------------------------------------+--------------------------------------+---------------+-----------------+

    $ openstack share lock show dc7ec691-a505-47d0-b2ec-8eb7fb9270e4
    +-----------------+--------------------------------------+
    | Field           | Value                                |
    +-----------------+--------------------------------------+
    | ID              | dc7ec691-a505-47d0-b2ec-8eb7fb9270e4 |
    | Resource Id     | 4c0b4d35-4ea8-4811-a1e2-a065c64225a8 |
    | Resource Type   | share                                |
    | Resource Action | delete                               |
    | Lock Context    | user                                 |
    | User Id         | 89de351d3b5744b9853ec4829aa0e714     |
    | Project Id      | db2e72fef7864bbbbf210f22da7f1158     |
    | Created At      | 2023-07-18T05:11:56.626667           |
    | Updated At      | None                                 |
    | Lock Reason     | None                                 |
    +-----------------+--------------------------------------+

* Resource lock in action:

  .. code-block:: console

    $ openstack share delete myshare
    Failed to delete share with name or ID 'myshare': Resource lock/s [dc7ec691-a505-47d0-b2ec-8eb7fb9270e4] prevent delete action. (HTTP 403) (Request-ID: req-331a8e31-e02a-40b2-accf-0f6dae1b6178)
    1 of 1 shares failed to delete.

* Delete a resource lock:

  .. code-block:: console

    $ openstack share lock delete dc7ec691-a505-47d0-b2ec-8eb7fb9270e4

Share backups
-------------

* Create backup

  .. code-block:: console

     $ openstack share backup create --name test5 --backup-options backup_type=eng_data_backup source_share
     +-------------------+--------------------------------------+
     | Field             | Value                                |
     +-------------------+--------------------------------------+
     | availability_zone | manila-zone-0                        |
     | backup_type       | backup_type1                         |
     | created_at        | 2024-03-11T18:15:32.183982           |
     | description       | None                                 |
     | host              | vm.openstack.opendev.com@nas_storage |
     | id                | 4b468327-d03f-4df7-97ef-c5230b5beafc |
     | name              | test5                                |
     | progress          | 0                                    |
     | restore_progress  | 0                                    |
     | share_id          | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 |
     | size              | 1                                    |
     | status            | creating                             |
     | topic             | None                                 |
     | updated_at        | None                                 |
     +-------------------+--------------------------------------+

* List backups

  .. code-block:: console

     $ openstack share backup list
     +--------------------------------------+-------+--------------------------------------+-----------+
     | ID                                   | Name  | Share ID                             | Status    |
     +--------------------------------------+-------+--------------------------------------+-----------+
     | 4b468327-d03f-4df7-97ef-c5230b5beafc | test5 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | creating  |
     | 8a9b3ce0-23bb-4923-b8ce-d0dd1f56b2b8 | test4 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     +--------------------------------------+-------+--------------------------------------+-----------+

     $ openstack share backup show test5
     +-------------------+------------------------------------------------+
     | Field             | Value                                          |
     +-------------------+------------------------------------------------+
     | availability_zone | manila-zone-0                                  |
     | backup_type       | backup_type1                                   |
     | created_at        | 2024-03-11T18:15:32.000000                     |
     | description       | None                                           |
     | host              | scs000215254-1.nb.openenglab.netapp.com@ontap1 |
     | id                | 4b468327-d03f-4df7-97ef-c5230b5beafc           |
     | name              | test5                                          |
     | progress          | 0                                              |
     | restore_progress  | 0                                              |
     | share_id          | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7           |
     | size              | 1                                              |
     | status            | creating                                       |
     | topic             | manila-share                                   |
     | updated_at        | 2024-03-11T18:15:32.000000                     |
     +-------------------+------------------------------------------------+

     $ openstack share backup list
     +--------------------------------------+-------+--------------------------------------+-----------+
     | ID                                   | Name  | Share ID                             | Status    |
     +--------------------------------------+-------+--------------------------------------+-----------+
     | 4b468327-d03f-4df7-97ef-c5230b5beafc | test5 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     | 8a9b3ce0-23bb-4923-b8ce-d0dd1f56b2b8 | test4 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     +--------------------------------------+-------+--------------------------------------+-----------+

* Restore backup

  .. code-block:: console

     $ openstack share backup restore test4

     $ openstack share backup list
     +--------------------------------------+-------+--------------------------------------+-----------+
     | ID                                   | Name  | Share ID                             | Status    |
     +--------------------------------------+-------+--------------------------------------+-----------+
     | 4b468327-d03f-4df7-97ef-c5230b5beafc | test5 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | available |
     | 8a9b3ce0-23bb-4923-b8ce-d0dd1f56b2b8 | test4 | 983c6dd5-ef93-4c73-9359-ef02fe3bbce7 | restoring |
     +--------------------------------------+-------+--------------------------------------+-----------+

* Delete backup

  .. code-block:: console

     $ openstack share backup delete test5
