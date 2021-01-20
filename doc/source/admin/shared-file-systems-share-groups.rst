..
      Copyright (c) 2017 Jun Zhong

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


============
Share groups
============

Share group support is available in Manila since the Ocata release. A share
group is a group of shares upon which users can perform group based operations,
such as taking a snapshot together. This framework is meant to allow migrating
or replicating a group of shares in unison in future releases of manila.
Support currently exists for creating group types and group specs, creating
groups of shares, and creating snapshots of groups. These group operations can
be performed using the command line client.

To create a share group, and access it, the following general concepts
are prerequisite knowledge:

#. To create a share group, use :command:`manila share-group-create` command.

#. You can specify the ``share-network``, :ref:`share group type <shared_file_systems_share_group_types>`,
   ``source-share-group-snapshot``, ``availability-zone``,
   :ref:`share type <shared_file_systems_share_types>`.

#. After the share group becomes available, use the :command:`manila create`
   command to create a share within the share group.

.. note::
   A share group is limited to a single backend, i.e. all shares created within
   a particular share group end up on the same backend. If the backend supports
   pools, the shares may be created within separate pools. So this feature is
   apt for those that would like co-locality of different shares.

Actions on a share group
~~~~~~~~~~~~~~~~~~~~~~~~

A few actions, such as extend & shrink, are inherently applicable only to
individual shares. One could theoretically apply extend to a group, increasing
the size of each member, but this would not be a use-case covered initially.
Any actions in this category must remain available to group members, and
other actions such as taking snapshots of group members can be allowed, but
actions such as migration or replication would be available only at the group
level and not on its members.

====================== ========================================================
Share Action           Share Group Action
====================== ========================================================
Create (share type)    Create (share types, group type)
Delete                 Delete (group)
Snapshot               Snapshot (may or may not be a consistent group snapshot)
Create from snapshot   Create from group snapshot
Clone                  Clone group (and all members) (planned)
Replicate              Replicate (planned)
Migrate                Migrate (planned)
Extend/shrink          N/A
====================== ========================================================

Creating a share with share group
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creating a share group type
---------------------------

In this example, we will create a new share group type and specify the
`consistent_snapshot_support` as an group-spec within the
share-group-type-create being used.

Use the :command:`manila type-list` command to get a share type.
Then use the share type to create a share group type.

.. code-block:: console

   $ manila type-list
   +--------------------------------------+---------------------+------------+------------+--------------------------------------+-----------------------------+
   | ID                                   | Name                | visibility | is_default | required_extra_specs                 | optional_extra_specs        |
   +--------------------------------------+---------------------+------------+------------+--------------------------------------+-----------------------------+
   | ee6287aa-448b-432b-a928-41ce9d8e149f | default_share_type  | public     | -          | driver_handles_share_servers : False |                             |
   +--------------------------------------+---------------------+------------+------------+--------------------------------------+-----------------------------+

Use the :command:`manila share-group-type-create` command to create a new
share group type. Specify the name and share types.

.. code-block:: console

   $ manila share-group-type-create group_type_for_cg default_share_type
   +------------+--------------------------------------+
   | Property   | Value                                |
   +------------+--------------------------------------+
   | is_default | -                                    |
   | ID         | cfe42f20-d13e-4348-9370-f0763e426db3 |
   | Visibility | public                               |
   | Name       | group_type_for_cg                    |
   +------------+--------------------------------------+

Use the :command:`manila share-group-type-key` command to set a group-spec to the
share group type.

.. code-block:: console

   $ manila share-group-type-key group_type_for_cg set consistent_snapshot_support=host

.. note::
   This command has no output. To verify the group-spec, use the
   :command:`manila share-group-type-specs-list` command and specify
   the share group type's name or ID as a parameter.

Creating a share group
----------------------

Use the :command:`manila share-group-create` command to create a share group.
Specify the share group type that we created.

.. code-block:: console

   $ manila share-group-create --share-group-type group_type_for_cg
   +--------------------------------+--------------------------------------+
   | Property                       | Value                                |
   +--------------------------------+--------------------------------------+
   | status                         | creating                             |
   | description                    | None                                 |
   | created_at                     | 2017-09-11T02:08:52.319921           |
   | source_share_group_snapshot_id | None                                 |
   | share_network_id               | None                                 |
   | share_server_id                | None                                 |
   | host                           | None                                 |
   | share_group_type_id            | cfe42f20-d13e-4348-9370-f0763e426db3 |
   | project_id                     | 87ba30b5315c40ec8ec5e3346112eae4     |
   | share_types                    | ee6287aa-448b-432b-a928-41ce9d8e149f |
   | id                             | ecf78d45-546a-48df-a969-c153e68f0376 |
   | name                           | None                                 |
   +--------------------------------+--------------------------------------+

.. note::
   One share group can include multiple share types. The share types are going
   to be inherited directly from the share group type.

Use the :command:`manila share-group-show` command to retrieve details of the share.
Specify the share ID or name as a parameter.

.. code-block:: console

   $ manila share-group-show ecf78d45-546a-48df-a969-c153e68f0376
   +--------------------------------+-------------------------------------------+
   | Property                       | Value                                     |
   +--------------------------------+-------------------------------------------+
   | status                         | available                                 |
   | description                    | None                                      |
   | created_at                     | 2017-09-11T02:08:53.000000                |
   | source_share_group_snapshot_id | None                                      |
   | share_network_id               | None                                      |
   | share_server_id                | None                                      |
   | host                           | ubuntu@generic2#test_pool                 |
   | share_group_type_id            | cfe42f20-d13e-4348-9370-f0763e426db3      |
   | project_id                     | 87ba30b5315c40ec8ec5e3346112eae4          |
   | share_types                    | ee6287aa-448b-432b-a928-41ce9d8e149f      |
   | id                             | ecf78d45-546a-48df-a969-c153e68f0376      |
   | name                           | None                                      |
   +--------------------------------+-------------------------------------------+

Create a share with the share group
-----------------------------------

Use the :command:`manila create` command to create a share. Specify the share
protocol, size, share group type and the share name.

.. code-block:: console

   $ manila create NFS 1 --share-group ecf78d45-546a-48df-a969-c153e68f0376 --name test_group_share_1
   +---------------------------------------+-------------------------------------------+
   | Property                              | Value                                     |
   +---------------------------------------+-------------------------------------------+
   | status                                | creating                                  |
   | share_type_name                       | default_share_type                        |
   | description                           | None                                      |
   | availability_zone                     | None                                      |
   | share_network_id                      | None                                      |
   | share_server_id                       | None                                      |
   | share_group_id                        | ecf78d45-546a-48df-a969-c153e68f0376      |
   | host                                  | ubuntu@generic2#test_pool                 |
   | revert_to_snapshot_support            | False                                     |
   | access_rules_status                   | active                                    |
   | snapshot_id                           | None                                      |
   | create_share_from_snapshot_support    | False                                     |
   | is_public                             | False                                     |
   | task_state                            | None                                      |
   | snapshot_support                      | False                                     |
   | id                                    | 21997eaf-712e-433e-8872-4ff085683657      |
   | size                                  | 1                                         |
   | source_share_group_snapshot_member_id | None                                      |
   | user_id                               | b7f2c522a5644a83b78b3f61f50c6d71          |
   | name                                  | test_group_share_1                        |
   | share_type                            | ee6287aa-448b-432b-a928-41ce9d8e149f      |
   | has_replicas                          | False                                     |
   | replication_type                      | None                                      |
   | created_at                            | 2017-09-11T02:28:16.000000                |
   | share_proto                           | NFS                                       |
   | mount_snapshot_support                | False                                     |
   | project_id                            | 87ba30b5315c40ec8ec5e3346112eae4          |
   | metadata                              | {}                                        |
   +---------------------------------------+-------------------------------------------+

Create another share with a same share group, and named 'test_group_share_2'.

.. code-block:: console

   $ manila create NFS 1 --share-group ecf78d45-546a-48df-a969-c153e68f0376 --name test_group_share_2
   +---------------------------------------+-------------------------------------------+
   | Property                              | Value                                     |
   +---------------------------------------+-------------------------------------------+
   | status                                | creating                                  |
   | share_type_name                       | default_share_type                        |
   | description                           | None                                      |
   | availability_zone                     | None                                      |
   | share_network_id                      | None                                      |
   | share_server_id                       | None                                      |
   | share_group_id                        | ecf78d45-546a-48df-a969-c153e68f0376      |
   | host                                  | ubuntu@generic2#test_pool                 |
   | revert_to_snapshot_support            | False                                     |
   | access_rules_status                   | active                                    |
   | snapshot_id                           | None                                      |
   | create_share_from_snapshot_support    | False                                     |
   | is_public                             | False                                     |
   | task_state                            | None                                      |
   | snapshot_support                      | False                                     |
   | id                                    | 8d34a9a3-3b8c-4771-af2c-66c78fe1e0b1      |
   | size                                  | 1                                         |
   | source_share_group_snapshot_member_id | None                                      |
   | user_id                               | b7f2c522a5644a83b78b3f61f50c6d71          |
   | name                                  | test_group_share_2                        |
   | share_type                            | ee6287aa-448b-432b-a928-41ce9d8e149f      |
   | has_replicas                          | False                                     |
   | replication_type                      | None                                      |
   | created_at                            | 2017-09-11T21:01:36.000000                |
   | share_proto                           | NFS                                       |
   | mount_snapshot_support                | False                                     |
   | project_id                            | 87ba30b5315c40ec8ec5e3346112eae4          |
   | metadata                              | {}                                        |
   +---------------------------------------+-------------------------------------------+


Creating a share group snapshot
-------------------------------

Create a share group sanpshot of the share group

Use the :command:`manila share-group-snapshot-create` command to create a
share group snapshot. Specify the share group ID or name.

.. code-block:: console

   $ manila share-group-snapshot-create  ecf78d45-546a-48df-a969-c153e68f0376
   +----------------+--------------------------------------+
   | Property       | Value                                |
   +----------------+--------------------------------------+
   | status         | creating                             |
   | name           | None                                 |
   | created_at     | 2017-09-11T21:04:54.612737           |
   | share_group_id | ecf78d45-546a-48df-a969-c153e68f0376 |
   | project_id     | 87ba30b5315c40ec8ec5e3346112eae4     |
   | id             | ac387240-08dc-4b23-80f6-ffc481e6c87a |
   | description    | None                                 |
   +----------------+--------------------------------------+

Show the members of the share group snapshot

Use the :command:`manila share-group-snapshot-create` command to see all
share members of share group snapshot. Specify the share group snapshot
ID or name.

.. code-block:: console

   $ manila share-group-snapshot-list-members  ac387240-08dc-4b23-80f6-ffc481e6c87a
   +--------------------------------------+------+
   | Share ID                             | Size |
   +--------------------------------------+------+
   | 21997eaf-712e-433e-8872-4ff085683657 | 1    |
   | 8d34a9a3-3b8c-4771-af2c-66c78fe1e0b1 | 1    |
   +--------------------------------------+------+

Show the details of the share group snapshot

.. code-block:: console

   $ manila share-group-snapshot-show ac387240-08dc-4b23-80f6-ffc481e6c87a
   +----------------+--------------------------------------+
   | Property       | Value                                |
   +----------------+--------------------------------------+
   | status         | available                            |
   | name           | None                                 |
   | created_at     | 2017-09-11T21:04:55.000000           |
   | share_group_id | ecf78d45-546a-48df-a969-c153e68f0376 |
   | project_id     | 87ba30b5315c40ec8ec5e3346112eae4     |
   | id             | ac387240-08dc-4b23-80f6-ffc481e6c87a |
   | description    | None                                 |
   +----------------+--------------------------------------+

Deleting share groups
---------------------

Use the :command:`manila share-group-delete <group_id>`
to delete share groups.

Deleting share group snapshots
------------------------------
Use the :command:`manila share-group-snapshot-delete <group_snapshot_id>`
to delete share a share group snapshot.

.. important::
    Before attempting to delete a share group or a share group snapshot, make
    sure that all its constituent shares and snapshots were deleted.
    Users will need to delete share group snapshots before attempting to delete
    shares within  ashare group or the group itself.
