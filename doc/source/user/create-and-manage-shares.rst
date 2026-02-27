.. _share:

========================
Create and manage shares
========================

.. contents:: :local:

General Concepts
----------------

A ``share`` is filesystem storage that you can create with manila. You can pick
a network protocol for the underlying storage, manage access and perform
lifecycle operations on the share via the ``openstack share`` command line
interface.

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

     $ openstack share limits show --absolute
     +------------------------------+-------+
     | Name                         | Value |
     +------------------------------+-------+
     | maxTotalShares               |    50 |
     | maxTotalShareSnapshots       |    50 |
     | maxTotalShareGigabytes       |  1000 |
     | maxTotalSnapshotGigabytes    |  1000 |
     | maxTotalShareNetworks        |    10 |
     | maxTotalShareGroups          |    50 |
     | maxTotalShareGroupSnapshots  |    50 |
     | maxTotalShareReplicas        |   100 |
     | maxTotalReplicaGigabytes     |  1000 |
     | maxTotalShareBackups         |    10 |
     | maxTotalBackupGigabytes      |  1000 |
     | totalSharesUsed              |     0 |
     | totalShareSnapshotsUsed      |     0 |
     | totalShareGigabytesUsed      |     0 |
     | totalSnapshotGigabytesUsed   |     0 |
     | totalShareNetworksUsed       |     0 |
     | totalShareGroupsUsed         |     0 |
     | totalShareGroupSnapshotsUsed |     0 |
     | totalShareReplicasUsed       |     0 |
     | totalReplicaGigabytesUsed    |     0 |
     | totalShareBackupsUsed        |     0 |
     | totalBackupGigabytesUsed     |     0 |
     +------------------------------+-------+

Share types
-----------

* List share types

  .. code-block:: console

     $ openstack share type list
     +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+
     | ID                                   | Name       | Visibility | Is Default | Required Extra Specs                 | Optional Extra Specs                      | Description |
     +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+
     | 57ba4538-6b25-4a53-a7e9-9f9c250a9655 | default    | public     | True       | driver_handles_share_servers : False | snapshot_support : True                   | None        |
     |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
     |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
     |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
     | 3827ada8-4dc1-4fd2-8f33-00283e798d54 | dhss_false | public     | False      | driver_handles_share_servers : False | snapshot_support : True                   | None        |
     |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
     |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
     |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
     | 5f5e225b-ec02-48fc-8daa-99a86a5a60df | dhss_true  | public     | False      | driver_handles_share_servers : True  | snapshot_support : True                   | None        |
     |                                      |            |            |            |                                      | create_share_from_snapshot_support : True |             |
     |                                      |            |            |            |                                      | revert_to_snapshot_support : True         |             |
     |                                      |            |            |            |                                      | mount_snapshot_support : True             |             |
     +--------------------------------------+------------+------------+------------+--------------------------------------+-------------------------------------------+-------------+

Share networks
--------------

* Create a share network.

  .. code-block:: console

     $ openstack share network create \
         --name mysharenetwork \
         --description "My Manila network" \
         --neutron-net-id 5edf25ef-73eb-4635-8be0-8246e7d7417b \
         --neutron-subnet-id 046cd84a-8938-4240-9ebd-ad5d8be10f20
     +-----------------------------------+----------------------------------------------------------+
     | Field                             | Value                                                    |
     +-----------------------------------+----------------------------------------------------------+
     | id                                | 5f19ae95-483c-4040-9a99-99fe109f6a8b                     |
     | name                              | mysharenetwork                                           |
     | project_id                        | 58951a7d00fd46f9a98bd038ed5d9e09                         |
     | created_at                        | 2026-04-04T07:13:36.675153                               |
     | updated_at                        | None                                                     |
     | description                       | My Manila network                                        |
     | status                            | active                                                   |
     | security_service_update_support   | True                                                     |
     | network_allocation_update_support | True                                                     |
     | share_network_subnets             |                                                          |
     |                                   | id = 4cf2d1f8-3c56-4e49-9f2a-62e1312ef574                |
     |                                   | availability_zone = None                                 |
     |                                   | created_at = 2026-04-04T07:13:36.706249                  |
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

     This Manila API does not validate the subnet information you supply right
     away. The validation is performed when creating a share with the share
     network. This is why, you do not see some subnet information populated on
     the share network resource until at least one share is created with it.

* List share networks.

  .. code-block:: console

     $ openstack share network list
     +--------------------------------------+----------------+
     | ID                                   | Name           |
     +--------------------------------------+----------------+
     | 5f19ae95-483c-4040-9a99-99fe109f6a8b | mysharenetwork |
     +--------------------------------------+----------------+

Create a share
--------------

* Create a share

  .. note::

     If you use a share type that has the extra specification
     ``driver_handles_share_servers=False``,
     you cannot use a share network to create your shares.

  .. code-block:: console

     $ openstack share create NFS 1 \
         --name myshare \
         --description "My Manila share" \
         --share-network mysharenetwork \
         --share-type dhss_true
     +---------------------------------------+--------------------------------------+
     | Field                                 | Value                                |
     +---------------------------------------+--------------------------------------+
     | id                                    | c8c7b376-364b-4b48-87d4-bba4609612fd |
     | size                                  | 1                                    |
     | availability_zone                     | None                                 |
     | created_at                            | 2026-04-04T07:13:52.667825           |
     | status                                | creating                             |
     | name                                  | myshare                              |
     | description                           | My Manila share                      |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09     |
     | snapshot_id                           | None                                 |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b |
     | share_proto                           | NFS                                  |
     | metadata                              | {}                                   |
     | share_type                            | 5f5e225b-ec02-48fc-8daa-99a86a5a60df |
     | is_public                             | False                                |
     | snapshot_support                      | True                                 |
     | task_state                            | None                                 |
     | share_type_name                       | dhss_true                            |
     | access_rules_status                   | active                               |
     | replication_type                      | None                                 |
     | has_replicas                          | False                                |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7     |
     | create_share_from_snapshot_support    | True                                 |
     | revert_to_snapshot_support            | True                                 |
     | share_group_id                        | None                                 |
     | source_share_group_snapshot_member_id | None                                 |
     | mount_snapshot_support                | True                                 |
     | progress                              | None                                 |
     +---------------------------------------+--------------------------------------+

* Show a share.

  .. code-block:: console

     $ openstack share show myshare
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | Field                                 | Value                                                                                                             |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | id                                    | c8c7b376-364b-4b48-87d4-bba4609612fd                                                                              |
     | size                                  | 1                                                                                                                 |
     | availability_zone                     | manila-zone-2                                                                                                     |
     | created_at                            | 2026-04-04T07:13:52.667825                                                                                        |
     | status                                | available                                                                                                         |
     | name                                  | myshare                                                                                                           |
     | description                           | My Manila share                                                                                                   |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09                                                                                  |
     | snapshot_id                           | None                                                                                                              |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b                                                                              |
     | share_proto                           | NFS                                                                                                               |
     | share_type                            | 5f5e225b-ec02-48fc-8daa-99a86a5a60df                                                                              |
     | is_public                             | False                                                                                                             |
     | snapshot_support                      | True                                                                                                              |
     | task_state                            | None                                                                                                              |
     | share_type_name                       | dhss_true                                                                                                         |
     | access_rules_status                   | active                                                                                                            |
     | replication_type                      | None                                                                                                              |
     | has_replicas                          | False                                                                                                             |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                                                                  |
     | create_share_from_snapshot_support    | True                                                                                                              |
     | revert_to_snapshot_support            | True                                                                                                              |
     | share_group_id                        | None                                                                                                              |
     | source_share_group_snapshot_member_id | None                                                                                                              |
     | mount_snapshot_support                | True                                                                                                              |
     | progress                              | 100%                                                                                                              |
     | export_locations                      |                                                                                                                   |
     |                                       | id = 94214735-4148-4fa7-b496-56d8a8d56008                                                                         |
     |                                       | path = 192.0.2.10:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = True                                                                                                  |
     |                                       | id = 3f0c4569-2567-4304-811e-373c35b34368                                                                         |
     |                                       | path = 192.0.2.11:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = False                                                                                                 |
     | properties                            |                                                                                                                   |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+

* List shares.

  .. code-block:: console

     $ openstack share list
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | ID                                   | Name    | Size | Share Proto | Status    | Is Public | Share Type Name | Host | Availability Zone |
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | c8c7b376-364b-4b48-87d4-bba4609612fd | myshare |    1 | NFS         | available | False     | dhss_true       |      | manila-zone-2     |
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+

* List share export locations.

  .. code-block:: console

     $ openstack share export location list myshare
     +--------------------------------------+------------------------------------------------------------------------------------------------------------+-----------+
     | ID                                   | Path                                                                                                       | Preferred |
     +--------------------------------------+------------------------------------------------------------------------------------------------------------+-----------+
     | 94214735-4148-4fa7-b496-56d8a8d56008 | 192.0.2.10:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   | True      |
     | 3f0c4569-2567-4304-811e-373c35b34368 | 192.0.2.11:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   | False     |
     +--------------------------------------+------------------------------------------------------------------------------------------------------------+-----------+

* Create a share using scheduler hints to specify the host.

  With scheduler hints, you can optionally specify the affinity and anti-affinity rules in relation to other shares.
  The scheduler will enforce these rules when determining where to create the share.
  Possible keys are ``same_host`` and ``different_host``, and the value must be the share name or id.

  .. code-block:: console

     $ openstack share create NFS 1 \
         --name myshare2 \
         --description "My Manila share - Different Host" \
         --share-type dhss_false \
         --scheduler-hint different_host=myshare

     +---------------------------------------+-----------------------------------------------------------------------+
     | Field                                 | Value                                                                 |
     +---------------------------------------+-----------------------------------------------------------------------+
     | id                                    | f1d4c7a8-1a8f-4029-aebb-e41ee9ee72cc                                  |
     | size                                  | 1                                                                     |
     | availability_zone                     | None                                                                  |
     | created_at                            | 2026-04-04T07:14:46.776109                                            |
     | status                                | creating                                                              |
     | name                                  | myshare2                                                              |
     | description                           | My Manila share - Different Host                                      |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09                                      |
     | snapshot_id                           | None                                                                  |
     | share_network_id                      | None                                                                  |
     | share_proto                           | NFS                                                                   |
     | metadata                              | {'__affinity_different_host': 'c8c7b376-364b-4b48-87d4-bba4609612fd'} |
     | share_type                            | 3827ada8-4dc1-4fd2-8f33-00283e798d54                                  |
     | is_public                             | False                                                                 |
     | snapshot_support                      | True                                                                  |
     | task_state                            | None                                                                  |
     | share_type_name                       | dhss_false                                                            |
     | access_rules_status                   | active                                                                |
     | replication_type                      | None                                                                  |
     | has_replicas                          | False                                                                 |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                      |
     | create_share_from_snapshot_support    | True                                                                  |
     | revert_to_snapshot_support            | True                                                                  |
     | share_group_id                        | None                                                                  |
     | source_share_group_snapshot_member_id | None                                                                  |
     | mount_snapshot_support                | True                                                                  |
     | progress                              | None                                                                  |
     +---------------------------------------+-----------------------------------------------------------------------+

  Share is created in a different host. An administrator can verify using
  ``--all-projects``:

  .. code-block:: console

     $ openstack share list --all-projects
     +--------------------------------------+----------+------+-------------+-----------+-----------+-----------------+-----------------------------------------------+-------------------+
     | ID                                   | Name     | Size | Share Proto | Status    | Is Public | Share Type Name | Host                                          | Availability Zone |
     +--------------------------------------+----------+------+-------------+-----------+-----------+-----------------+-----------------------------------------------+-------------------+
     | c8c7b376-364b-4b48-87d4-bba4609612fd | myshare  |    1 | NFS         | available | False     | dhss_true       | manila-intern-testing@lima#pool_GAMMA         | manila-zone-2     |
     | f1d4c7a8-1a8f-4029-aebb-e41ee9ee72cc | myshare2 |    1 | NFS         | available | False     | dhss_false      | manila-intern-testing@bogota#pool_DELTA       | manila-zone-3     |
     +--------------------------------------+----------+------+-------------+-----------+-----------+-----------------+-----------------------------------------------+-------------------+

* Create a share using `mount_point_name`.

  When `mount_point_name_support` is enabled by your administrator, you
  can specify a custom mount point name during share creation. This name
  will be used in conjunction with the prefix set by the administrator
  to form the share's export location.

  The general workflow for using `mount_point_name`:

  - ``Creating a new share``: Specify a custom `mount_point_name` using the
    `--mount-point-name` flag. The `mount_point_name` should not exceed 255
    characters in length.

  .. code-block:: console

     $ openstack share create NFS 1 --share-type gold_provisioning_prefix \
         --name MyShare --mount-point-name mount_abc1 \
         --share-network mysharenetwork
     +---------------------------------------+--------------------------------------+
     | Field                                 | Value                                |
     +---------------------------------------+--------------------------------------+
     | id                                    | 138a6884-7a9b-4d9a-9ac1-f565701a4b83 |
     | size                                  | 1                                    |
     | availability_zone                     | None                                 |
     | created_at                            | 2026-04-04T08:32:50.819345           |
     | status                                | creating                             |
     | name                                  | MyShare                              |
     | description                           | None                                 |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09     |
     | snapshot_id                           | None                                 |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b |
     | share_proto                           | NFS                                  |
     | metadata                              | {}                                   |
     | share_type                            | ee1995d8-6827-4711-a58d-38ee00f24a75 |
     | is_public                             | False                                |
     | snapshot_support                      | False                                |
     | task_state                            | None                                 |
     | share_type_name                       | gold_provisioning_prefix             |
     | access_rules_status                   | active                               |
     | replication_type                      | None                                 |
     | has_replicas                          | False                                |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7     |
     | create_share_from_snapshot_support    | False                                |
     | revert_to_snapshot_support            | False                                |
     | share_group_id                        | None                                 |
     | source_share_group_snapshot_member_id | None                                 |
     | mount_snapshot_support                | False                                |
     | progress                              | None                                 |
     +---------------------------------------+--------------------------------------+

* To view the details of a share created with custom mount_point_name.

  .. code-block:: console

     $ openstack share show 138a6884-7a9b-4d9a-9ac1-f565701a4b83
     +---------------------------------------+----------------------------------------------------------------------+
     | Field                                 | Value                                                                |
     +---------------------------------------+----------------------------------------------------------------------+
     | id                                    | 138a6884-7a9b-4d9a-9ac1-f565701a4b83                                 |
     | size                                  | 1                                                                    |
     | availability_zone                     | manila-zone-2                                                        |
     | created_at                            | 2026-04-04T08:32:50.819345                                           |
     | status                                | available                                                            |
     | name                                  | MyShare                                                              |
     | description                           | None                                                                 |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09                                     |
     | snapshot_id                           | None                                                                 |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b                                 |
     | share_proto                           | NFS                                                                  |
     | share_type                            | ee1995d8-6827-4711-a58d-38ee00f24a75                                 |
     | is_public                             | False                                                                |
     | snapshot_support                      | False                                                                |
     | task_state                            | None                                                                 |
     | share_type_name                       | gold_provisioning_prefix                                             |
     | access_rules_status                   | active                                                               |
     | replication_type                      | None                                                                 |
     | has_replicas                          | False                                                                |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                     |
     | create_share_from_snapshot_support    | False                                                                |
     | revert_to_snapshot_support            | False                                                                |
     | share_group_id                        | None                                                                 |
     | source_share_group_snapshot_member_id | None                                                                 |
     | mount_snapshot_support                | False                                                                |
     | progress                              | 100%                                                                 |
     | export_locations                      |                                                                      |
     |                                       | id = 1f5d8a51-965e-4062-a1e1-03ca146ad277                            |
     |                                       | path = 192.0.2.10:/gold_mount_abc1                                   |
     |                                       | preferred = True                                                     |
     |                                       | id = ea7c936a-d94b-47bd-8a35-4b2f1f7b5e5a                            |
     |                                       | path = 192.0.2.11:/gold_mount_abc1                                   |
     |                                       | preferred = False                                                    |
     | properties                            |                                                                      |
     +---------------------------------------+----------------------------------------------------------------------+


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

     +---------------------------------------+--------------------------------------+
     | Field                                 | Value                                |
     +---------------------------------------+--------------------------------------+
     | id                                    | 7c69b887-8490-41f9-bb5d-6e8e6bffca76 |
     | size                                  | 1                                    |
     | availability_zone                     | None                                 |
     | created_at                            | 2026-04-04T07:24:14.583291           |
     | status                                | creating                             |
     | name                                  | myshare3                             |
     | description                           | My Manila share - Encrypted          |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09     |
     | snapshot_id                           | None                                 |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b |
     | share_proto                           | NFS                                  |
     | metadata                              | {}                                   |
     | share_type                            | b4c0453c-6c91-4b2e-a5a3-f92a7a481c17 |
     | is_public                             | False                                |
     | snapshot_support                      | True                                 |
     | task_state                            | None                                 |
     | share_type_name                       | encrypted_share_type                 |
     | access_rules_status                   | active                               |
     | replication_type                      | None                                 |
     | has_replicas                          | False                                |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7     |
     | create_share_from_snapshot_support    | True                                 |
     | revert_to_snapshot_support            | True                                 |
     | share_group_id                        | None                                 |
     | source_share_group_snapshot_member_id | None                                 |
     | mount_snapshot_support                | True                                 |
     | progress                              | None                                 |
     | encryption_key_ref                    | 86babe9b-7277-4c3a-a081-6eb3eac9231d |
     +---------------------------------------+--------------------------------------+


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

     $ openstack share access create myshare \
         ip 198.51.100.0/24 --properties key1=value1
     +--------------+--------------------------------------+
     | Field        | Value                                |
     +--------------+--------------------------------------+
     | id           | 95dcca99-6b3a-433d-a324-212268beca28 |
     | share_id     | c8c7b376-364b-4b48-87d4-bba4609612fd |
     | access_level | rw                                   |
     | access_to    | 198.51.100.0/24                      |
     | access_type  | ip                                   |
     | state        | queued_to_apply                      |
     | access_key   | None                                 |
     | created_at   | 2026-04-04T07:15:41.985379           |
     | updated_at   | None                                 |
     | properties   | key1 : value1                        |
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

     $ openstack share access list myshare
     +--------------------------------------+-------------+-----------------+--------------+--------+------------+----------------------------+----------------------------+
     | ID                                   | Access Type | Access To       | Access Level | State  | Access Key | Created At                 | Updated At                 |
     +--------------------------------------+-------------+-----------------+--------------+--------+------------+----------------------------+----------------------------+
     | 95dcca99-6b3a-433d-a324-212268beca28 | ip          | 198.51.100.0/24 | rw           | active | None       | 2026-04-04T07:15:41.985379 | 2026-04-04T07:15:44.977918 |
     +--------------------------------------+-------------+-----------------+--------------+--------+------------+----------------------------+----------------------------+

  An access rule is created.

Allow read-only access
~~~~~~~~~~~~~~~~~~~~~~

* Allow access.

  .. code-block:: console

     $ openstack share access create myshare \
         ip 2001:DB8:7ee0:3de4::/64 --access-level ro
     +--------------+--------------------------------------+
     | Field        | Value                                |
     +--------------+--------------------------------------+
     | id           | 7112dedf-bcf6-46c8-a3c1-5f4068753770 |
     | share_id     | c8c7b376-364b-4b48-87d4-bba4609612fd |
     | access_level | ro                                   |
     | access_to    | 2001:DB8:7ee0:3de4::/64              |
     | access_type  | ip                                   |
     | state        | queued_to_apply                      |
     | access_key   | None                                 |
     | created_at   | 2026-04-04T07:15:54.852659           |
     | updated_at   | None                                 |
     | properties   |                                      |
     +--------------+--------------------------------------+

* List access.

  .. code-block:: console

     $ openstack share access list myshare
     +--------------------------------------+-------------+--------------------------+--------------+--------+------------+----------------------------+----------------------------+
     | ID                                   | Access Type | Access To                | Access Level | State  | Access Key | Created At                 | Updated At                 |
     +--------------------------------------+-------------+--------------------------+--------------+--------+------------+----------------------------+----------------------------+
     | 7112dedf-bcf6-46c8-a3c1-5f4068753770 | ip          | 2001:DB8:7ee0:3de4::/64  | ro           | active | None       | 2026-04-04T07:15:54.852659 | 2026-04-04T07:15:57.661621 |
     | 95dcca99-6b3a-433d-a324-212268beca28 | ip          | 198.51.100.0/24          | rw           | active | None       | 2026-04-04T07:15:41.985379 | 2026-04-04T07:15:44.977918 |
     +--------------------------------------+-------------+--------------------------+--------------+--------+------------+----------------------------+----------------------------+

  Another access rule is created.

.. note::

  In case one or more access rules had its visibility locked, you might not be
  able to see the content of the fields containing sensitive information
  (``access_to`` and ``access_key``).

Update access rules metadata
----------------------------

#. Add a new metadata.

   .. code-block:: console

      $ openstack share access set \
          95dcca99-6b3a-433d-a324-212268beca28 \
          --property key2=value2
      $ openstack share access show 95dcca99-6b3a-433d-a324-212268beca28
      +--------------+--------------------------------------+
      | Field        | Value                                |
      +--------------+--------------------------------------+
      | id           | 95dcca99-6b3a-433d-a324-212268beca28 |
      | share_id     | c8c7b376-364b-4b48-87d4-bba4609612fd |
      | access_level | rw                                   |
      | access_to    | 198.51.100.0/24                      |
      | access_type  | ip                                   |
      | state        | active                               |
      | access_key   | None                                 |
      | created_at   | 2026-04-04T07:15:41.985379           |
      | updated_at   | 2026-04-04T07:15:44.977918           |
      | properties   | key1 : value1                        |
      |              | key2 : value2                        |
      +--------------+--------------------------------------+

#. Remove a metadata key value.

   .. code-block:: console

      $ openstack share access unset \
          95dcca99-6b3a-433d-a324-212268beca28 --property key1
      $ openstack share access show 95dcca99-6b3a-433d-a324-212268beca28
      +--------------+--------------------------------------+
      | Field        | Value                                |
      +--------------+--------------------------------------+
      | id           | 95dcca99-6b3a-433d-a324-212268beca28 |
      | share_id     | c8c7b376-364b-4b48-87d4-bba4609612fd |
      | access_level | rw                                   |
      | access_to    | 198.51.100.0/24                      |
      | access_type  | ip                                   |
      | state        | active                               |
      | access_key   | None                                 |
      | created_at   | 2026-04-04T07:15:41.985379           |
      | updated_at   | 2026-04-04T07:15:44.977918           |
      | properties   | key2 : value2                        |
      +--------------+--------------------------------------+

Deny access
-----------

* Deny access.

  .. code-block:: console

     $ openstack share access delete myshare \
         7112dedf-bcf6-46c8-a3c1-5f4068753770
     $ openstack share access delete myshare \
         95dcca99-6b3a-433d-a324-212268beca28

.. note::

  Starting from the 2023.2 (Bobcat) release, it is possible to prevent the
  deletion of an access rule. In case you have placed a deletion lock during
  the access rule creation, the ``--unrestrict`` argument from the Manila's
  OpenStack Client must be used in the request to revoke the access.

* List access.

  .. code-block:: console

     $ openstack share access list myshare

  The access rules are removed.

Create snapshot
---------------

* Create a snapshot.

  .. note::

     To create a snapshot, the share type of the share must contain the
     capability extra-spec ``snapshot_support=True``.

  .. code-block:: console

     $ openstack share snapshot create --name mysnap \
         --description "My Manila snapshot" myshare
     +-------------+--------------------------------------+
     | Field       | Value                                |
     +-------------+--------------------------------------+
     | id          | 87681665-e1c9-455e-a23e-6fc5f2af9bb8 |
     | share_id    | c8c7b376-364b-4b48-87d4-bba4609612fd |
     | share_size  | 1                                    |
     | created_at  | 2026-04-04T07:16:51.648431           |
     | status      | creating                             |
     | name        | mysnap                               |
     | description | My Manila snapshot                   |
     | size        | 1                                    |
     | share_proto | NFS                                  |
     | user_id     | a6c6f585fe5249cbb91426b37e1161a7     |
     | project_id  | 58951a7d00fd46f9a98bd038ed5d9e09     |
     | metadata    | {}                                   |
     +-------------+--------------------------------------+

* List snapshots.

  .. code-block:: console

     $ openstack share snapshot list
     +--------------------------------------+--------+
     | ID                                   | Name   |
     +--------------------------------------+--------+
     | 87681665-e1c9-455e-a23e-6fc5f2af9bb8 | mysnap |
     +--------------------------------------+--------+


Mount a snapshot
----------------

* Allow access to the snapshot.

  .. note::

     To mount a snapshot, the share type of the parent share must contain the
     capability extra-spec ``mount_snapshot_support=True``.

  .. code-block:: console

     $ openstack share snapshot access create mysnap ip 198.51.100.0/24
     +-------------+--------------------------------------+
     | Field       | Value                                |
     +-------------+--------------------------------------+
     | id          | ccc0c1d6-caaa-48f1-8974-332dfeb4b3d9 |
     | access_type | ip                                   |
     | access_to   | 198.51.100.0/24                      |
     | state       | queued_to_apply                      |
     +-------------+--------------------------------------+

* List snapshot access.

  .. code-block:: console

     $ openstack share snapshot access list mysnap
     +--------------------------------------+-------------+-----------------+--------+
     | ID                                   | Access Type | Access To       | State  |
     +--------------------------------------+-------------+-----------------+--------+
     | ccc0c1d6-caaa-48f1-8974-332dfeb4b3d9 | ip          | 198.51.100.0/24 | active |
     +--------------------------------------+-------------+-----------------+--------+

Then proceed to mounting the snapshot on the clients whose access was created.

* Delete snapshot access rule.

  .. code-block:: console

     $ openstack share snapshot access delete mysnap \
         ccc0c1d6-caaa-48f1-8974-332dfeb4b3d9


Create share from snapshot
--------------------------

* Create a share from a snapshot.

  .. note::

     To create a share from a snapshot, the share type of the parent share
     must contain the capability extra-spec
     ``create_share_from_snapshot_support=True``.

  .. code-block:: console

     $ openstack share create NFS 1 \
         --snapshot-id 87681665-e1c9-455e-a23e-6fc5f2af9bb8 \
         --share-network mysharenetwork \
         --name mysharefromsnap
     +---------------------------------------+--------------------------------------+
     | Field                                 | Value                                |
     +---------------------------------------+--------------------------------------+
     | id                                    | d1d594c1-d603-41c3-85ce-8a136f9d259e |
     | size                                  | 1                                    |
     | availability_zone                     | manila-zone-2                        |
     | created_at                            | 2026-04-04T07:17:25.755333           |
     | status                                | creating                             |
     | name                                  | mysharefromsnap                      |
     | description                           | None                                 |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09     |
     | snapshot_id                           | 87681665-e1c9-455e-a23e-6fc5f2af9bb8 |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b |
     | share_proto                           | NFS                                  |
     | metadata                              | {}                                   |
     | share_type                            | 5f5e225b-ec02-48fc-8daa-99a86a5a60df |
     | is_public                             | False                                |
     | snapshot_support                      | True                                 |
     | task_state                            | None                                 |
     | share_type_name                       | dhss_true                            |
     | access_rules_status                   | active                               |
     | replication_type                      | None                                 |
     | has_replicas                          | False                                |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7     |
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
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | ID                                   | Name            | Size | Share Proto | Status    | Is Public | Share Type Name | Host | Availability Zone |
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | c8c7b376-364b-4b48-87d4-bba4609612fd | myshare         |    1 | NFS         | available | False     | dhss_true       |      | manila-zone-2     |
     | f1d4c7a8-1a8f-4029-aebb-e41ee9ee72cc | myshare2        |    1 | NFS         | available | False     | dhss_false      |      | manila-zone-3     |
     | d1d594c1-d603-41c3-85ce-8a136f9d259e | mysharefromsnap |    1 | NFS         | available | False     | dhss_true       |      | manila-zone-2     |
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+

* Show the share created from snapshot.

  .. code-block:: console

     $ openstack share show mysharefromsnap
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | Field                                 | Value                                                                                                             |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | id                                    | d1d594c1-d603-41c3-85ce-8a136f9d259e                                                                              |
     | size                                  | 1                                                                                                                 |
     | availability_zone                     | manila-zone-2                                                                                                     |
     | created_at                            | 2026-04-04T07:17:25.755333                                                                                        |
     | status                                | available                                                                                                         |
     | name                                  | mysharefromsnap                                                                                                   |
     | description                           | None                                                                                                              |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09                                                                                  |
     | snapshot_id                           | 87681665-e1c9-455e-a23e-6fc5f2af9bb8                                                                              |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b                                                                              |
     | share_proto                           | NFS                                                                                                               |
     | share_type                            | 5f5e225b-ec02-48fc-8daa-99a86a5a60df                                                                              |
     | is_public                             | False                                                                                                             |
     | snapshot_support                      | True                                                                                                              |
     | task_state                            | None                                                                                                              |
     | share_type_name                       | dhss_true                                                                                                         |
     | access_rules_status                   | active                                                                                                            |
     | replication_type                      | None                                                                                                              |
     | has_replicas                          | False                                                                                                             |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                                                                  |
     | create_share_from_snapshot_support    | True                                                                                                              |
     | revert_to_snapshot_support            | True                                                                                                              |
     | share_group_id                        | None                                                                                                              |
     | source_share_group_snapshot_member_id | None                                                                                                              |
     | mount_snapshot_support                | True                                                                                                              |
     | progress                              | 100%                                                                                                              |
     | export_locations                      |                                                                                                                   |
     |                                       | id = a0799f73-fc87-4ef5-b46f-197df18f89c7                                                                         |
     |                                       | path = 192.0.2.10:/sharevolumes/share_d1d594c1_d603_41c3_85ce_8a136f9d259e_c7ca5db9_ea48_4bcd_aa3b_b41ec9a81774   |
     |                                       | preferred = True                                                                                                  |
     |                                       | id = 534a8730-e8dd-41fa-b9ba-2376080d398c                                                                         |
     |                                       | path = 192.0.2.11:/sharevolumes/share_d1d594c1_d603_41c3_85ce_8a136f9d259e_c7ca5db9_ea48_4bcd_aa3b_b41ec9a81774   |
     |                                       | preferred = False                                                                                                 |
     | properties                            |                                                                                                                   |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+

Delete share
------------

* Delete a share.

  .. code-block:: console

     $ openstack share delete mysharefromsnap

* List shares.

  .. code-block:: console

     $ openstack share list
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | ID                                   | Name            | Size | Share Proto | Status    | Is Public | Share Type Name | Host | Availability Zone |
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | c8c7b376-364b-4b48-87d4-bba4609612fd | myshare         |    1 | NFS         | available | False     | dhss_true       |      | manila-zone-2     |
     | f1d4c7a8-1a8f-4029-aebb-e41ee9ee72cc | myshare2        |    1 | NFS         | available | False     | dhss_false      |      | manila-zone-3     |
     | d1d594c1-d603-41c3-85ce-8a136f9d259e | mysharefromsnap |    1 | NFS         | deleting  | False     | dhss_true       |      | manila-zone-2     |
     +--------------------------------------+-----------------+------+-------------+-----------+-----------+-----------------+------+-------------------+

  The share is being deleted.

Delete snapshot
---------------

* Delete a snapshot.

  .. code-block:: console

     $ openstack share snapshot delete mysnap

* List snapshots after deleting.

  .. code-block:: console

     $ openstack share snapshot list


  The snapshot is deleted.

Extend share
------------

* Extend share.

  .. code-block:: console

     $ openstack share resize myshare 2

* Show the share while it is being extended.

  .. code-block:: console

     $ openstack share show myshare
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | Field                                 | Value                                                                                                             |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | id                                    | c8c7b376-364b-4b48-87d4-bba4609612fd                                                                              |
     | size                                  | 1                                                                                                                 |
     | availability_zone                     | manila-zone-2                                                                                                     |
     | created_at                            | 2026-04-04T07:13:52.667825                                                                                        |
     | status                                | extending                                                                                                         |
     | name                                  | myshare                                                                                                           |
     | description                           | My Manila share                                                                                                   |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09                                                                                  |
     | snapshot_id                           | None                                                                                                              |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b                                                                              |
     | share_proto                           | NFS                                                                                                               |
     | share_type                            | 5f5e225b-ec02-48fc-8daa-99a86a5a60df                                                                              |
     | is_public                             | False                                                                                                             |
     | snapshot_support                      | True                                                                                                              |
     | task_state                            | None                                                                                                              |
     | share_type_name                       | dhss_true                                                                                                         |
     | access_rules_status                   | active                                                                                                            |
     | replication_type                      | None                                                                                                              |
     | has_replicas                          | False                                                                                                             |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                                                                  |
     | create_share_from_snapshot_support    | True                                                                                                              |
     | revert_to_snapshot_support            | True                                                                                                              |
     | share_group_id                        | None                                                                                                              |
     | source_share_group_snapshot_member_id | None                                                                                                              |
     | mount_snapshot_support                | True                                                                                                              |
     | progress                              | 100%                                                                                                              |
     | export_locations                      |                                                                                                                   |
     |                                       | id = 94214735-4148-4fa7-b496-56d8a8d56008                                                                         |
     |                                       | path = 192.0.2.10:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = True                                                                                                  |
     |                                       | id = 3f0c4569-2567-4304-811e-373c35b34368                                                                         |
     |                                       | path = 192.0.2.11:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = False                                                                                                 |
     | properties                            |                                                                                                                   |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+

* Show the share after it is extended.

  .. code-block:: console

     $ openstack share show myshare
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | Field                                 | Value                                                                                                             |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | id                                    | c8c7b376-364b-4b48-87d4-bba4609612fd                                                                              |
     | size                                  | 2                                                                                                                 |
     | availability_zone                     | manila-zone-2                                                                                                     |
     | created_at                            | 2026-04-04T07:13:52.667825                                                                                        |
     | status                                | available                                                                                                         |
     | name                                  | myshare                                                                                                           |
     | description                           | My Manila share                                                                                                   |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09                                                                                  |
     | snapshot_id                           | None                                                                                                              |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b                                                                              |
     | share_proto                           | NFS                                                                                                               |
     | share_type                            | 5f5e225b-ec02-48fc-8daa-99a86a5a60df                                                                              |
     | is_public                             | False                                                                                                             |
     | snapshot_support                      | True                                                                                                              |
     | task_state                            | None                                                                                                              |
     | share_type_name                       | dhss_true                                                                                                         |
     | access_rules_status                   | active                                                                                                            |
     | replication_type                      | None                                                                                                              |
     | has_replicas                          | False                                                                                                             |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                                                                  |
     | create_share_from_snapshot_support    | True                                                                                                              |
     | revert_to_snapshot_support            | True                                                                                                              |
     | share_group_id                        | None                                                                                                              |
     | source_share_group_snapshot_member_id | None                                                                                                              |
     | mount_snapshot_support                | True                                                                                                              |
     | progress                              | 100%                                                                                                              |
     | export_locations                      |                                                                                                                   |
     |                                       | id = 94214735-4148-4fa7-b496-56d8a8d56008                                                                         |
     |                                       | path = 192.0.2.10:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = True                                                                                                  |
     |                                       | id = 3f0c4569-2567-4304-811e-373c35b34368                                                                         |
     |                                       | path = 192.0.2.11:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = False                                                                                                 |
     | properties                            |                                                                                                                   |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+

Shrink share
------------

* Shrink a share.

  .. code-block:: console

     $ openstack share resize myshare 1

* Show the share while it is being shrunk.

  .. code-block:: console

     $ openstack share show myshare
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | Field                                 | Value                                                                                                             |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | id                                    | c8c7b376-364b-4b48-87d4-bba4609612fd                                                                              |
     | size                                  | 2                                                                                                                 |
     | availability_zone                     | manila-zone-2                                                                                                     |
     | created_at                            | 2026-04-04T07:13:52.667825                                                                                        |
     | status                                | shrinking                                                                                                         |
     | name                                  | myshare                                                                                                           |
     | description                           | My Manila share                                                                                                   |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09                                                                                  |
     | snapshot_id                           | None                                                                                                              |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b                                                                              |
     | share_proto                           | NFS                                                                                                               |
     | share_type                            | 5f5e225b-ec02-48fc-8daa-99a86a5a60df                                                                              |
     | is_public                             | False                                                                                                             |
     | snapshot_support                      | True                                                                                                              |
     | task_state                            | None                                                                                                              |
     | share_type_name                       | dhss_true                                                                                                         |
     | access_rules_status                   | active                                                                                                            |
     | replication_type                      | None                                                                                                              |
     | has_replicas                          | False                                                                                                             |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                                                                  |
     | create_share_from_snapshot_support    | True                                                                                                              |
     | revert_to_snapshot_support            | True                                                                                                              |
     | share_group_id                        | None                                                                                                              |
     | source_share_group_snapshot_member_id | None                                                                                                              |
     | mount_snapshot_support                | True                                                                                                              |
     | progress                              | 100%                                                                                                              |
     | export_locations                      |                                                                                                                   |
     |                                       | id = 94214735-4148-4fa7-b496-56d8a8d56008                                                                         |
     |                                       | path = 192.0.2.10:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = True                                                                                                  |
     |                                       | id = 3f0c4569-2567-4304-811e-373c35b34368                                                                         |
     |                                       | path = 192.0.2.11:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = False                                                                                                 |
     | properties                            |                                                                                                                   |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+

* Show the share after it is being shrunk.

  .. code-block:: console

     $ openstack share show myshare
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | Field                                 | Value                                                                                                             |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | id                                    | c8c7b376-364b-4b48-87d4-bba4609612fd                                                                              |
     | size                                  | 1                                                                                                                 |
     | availability_zone                     | manila-zone-2                                                                                                     |
     | created_at                            | 2026-04-04T07:13:52.667825                                                                                        |
     | status                                | available                                                                                                         |
     | name                                  | myshare                                                                                                           |
     | description                           | My Manila share                                                                                                   |
     | project_id                            | 58951a7d00fd46f9a98bd038ed5d9e09                                                                                  |
     | snapshot_id                           | None                                                                                                              |
     | share_network_id                      | 5f19ae95-483c-4040-9a99-99fe109f6a8b                                                                              |
     | share_proto                           | NFS                                                                                                               |
     | share_type                            | 5f5e225b-ec02-48fc-8daa-99a86a5a60df                                                                              |
     | is_public                             | False                                                                                                             |
     | snapshot_support                      | True                                                                                                              |
     | task_state                            | None                                                                                                              |
     | share_type_name                       | dhss_true                                                                                                         |
     | access_rules_status                   | active                                                                                                            |
     | replication_type                      | None                                                                                                              |
     | has_replicas                          | False                                                                                                             |
     | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                                                                  |
     | create_share_from_snapshot_support    | True                                                                                                              |
     | revert_to_snapshot_support            | True                                                                                                              |
     | share_group_id                        | None                                                                                                              |
     | source_share_group_snapshot_member_id | None                                                                                                              |
     | mount_snapshot_support                | True                                                                                                              |
     | progress                              | 100%                                                                                                              |
     | export_locations                      |                                                                                                                   |
     |                                       | id = 94214735-4148-4fa7-b496-56d8a8d56008                                                                         |
     |                                       | path = 192.0.2.10:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = True                                                                                                  |
     |                                       | id = 3f0c4569-2567-4304-811e-373c35b34368                                                                         |
     |                                       | path = 192.0.2.11:/sharevolumes/share_c8c7b376_364b_4b48_87d4_bba4609612fd_2adf9d85_855d_4a1e_af0a_bc44cb6b42db   |
     |                                       | preferred = False                                                                                                 |
     | properties                            |                                                                                                                   |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+

Share metadata
--------------

* Set metadata items on your share

  .. code-block:: console

     $ openstack share set myshare \
         --property purpose='storing financial data for analysis' \
         --property year_started=2020

* Show share metadata

  .. code-block:: console

     $ openstack share show myshare
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | Field                                 | Value                                                                                                             |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+
     | ...                                   | ...                                                                                                               |
     | properties                            | purpose='storing financial data for analysis', year_started='2020'                                                |
     | ...                                   | ...                                                                                                               |
     +---------------------------------------+-------------------------------------------------------------------------------------------------------------------+

* Query share list with metadata

  .. code-block:: console

     $ openstack share list --property year_started=2020
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | ID                                   | Name    | Size | Share Proto | Status    | Is Public | Share Type Name | Host | Availability Zone |
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+
     | c8c7b376-364b-4b48-87d4-bba4609612fd | myshare |    1 | NFS         | available | False     | dhss_true       |      | manila-zone-2     |
     +--------------------------------------+---------+------+-------------+-----------+-----------+-----------------+------+-------------------+

* Unset share metadata

  .. code-block:: console

     $ openstack share unset myshare --property year_started

Share revert to snapshot
------------------------

* Share revert to snapshot

  .. note::

   -  To revert a share to its snapshot, the share type of the share must
      contain the capability extra-spec ``revert_to_snapshot_support=True``.
   -  The revert operation can only be performed to the most recent available
      snapshot of the share known to Manila. If revert to an earlier snapshot
      is desired, later snapshots must explicitly be deleted.

  .. code-block:: console

     $ openstack share revert mysnapshot

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

     $ openstack share transfer create myshare --name mytransfer
     +------------------------+--------------------------------------+
     | Field                  | Value                                |
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

     $ openstack share transfer accept \
         1c56314e-7e97-455a-bbde-83828db038d4 af429e22e0abc31d

* Delete a transfer

  .. code-block:: console

     $ openstack share transfer delete 1c56314e-7e97-455a-bbde-83828db038d4

* List transfers

  .. code-block:: console

     $ openstack share transfer list
     +--------------------------------------+------------+---------------+--------------------------------------+
     | ID                                   | Name       | Resource Type | Resource Id                          |
     +--------------------------------------+------------+---------------+--------------------------------------+
     | 1c56314e-7e97-455a-bbde-83828db038d4 | mytransfer | share         | 5573c214-ef79-4fb7-83f8-8c01fbe847f7 |
     +--------------------------------------+------------+---------------+--------------------------------------+

* Show a share transfer

  .. code-block:: console

     $ openstack share transfer show 1c56314e-7e97-455a-bbde-83828db038d4
     +------------------------+--------------------------------------+
     | Field                  | Value                                |
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
     +-------------+--------------------------------------+
     | Field       | Value                                |
     +-------------+--------------------------------------+
     | id          | 00a82c82-cb49-414b-a334-c1a1e9b360d5 |
     | share_id    | c8c7b376-364b-4b48-87d4-bba4609612fd |
     | share_size  | 1                                    |
     | created_at  | 2026-04-04T07:39:52.555692           |
     | status      | creating                             |
     | name        | mysnapshot                           |
     | description | None                                 |
     | size        | 1                                    |
     | share_proto | NFS                                  |
     | user_id     | a6c6f585fe5249cbb91426b37e1161a7     |
     | project_id  | 58951a7d00fd46f9a98bd038ed5d9e09     |
     | metadata    | key1 : value1                        |
     |             | key2 : value2                        |
     +-------------+--------------------------------------+

* Set metadata items on your share snapshot

  .. code-block:: console

     $ openstack share snapshot set mysnapshot --property key1=value


* Query snapshot list with metadata

  .. code-block:: console

     $ openstack share snapshot list --property key1=value1
     +--------------------------------------+------------+
     | ID                                   | Name       |
     +--------------------------------------+------------+
     | 00a82c82-cb49-414b-a334-c1a1e9b360d5 | mysnapshot |
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

     $ openstack share backup create --name test5 \
         --backup-options backup_type=eng_data_backup \
         source_share
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
