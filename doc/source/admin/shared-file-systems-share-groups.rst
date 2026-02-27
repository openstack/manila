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

#. To create a share group, use :command:`openstack share group create` command.

#. You can specify the ``share-network``, :ref:`share group type <shared_file_systems_share_group_types>`,
   ``source-share-group-snapshot``, ``availability-zone``,
   :ref:`share type <shared_file_systems_share_types>`.

#. After the share group becomes available, use the :command:`openstack share create`
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

Use the :command:`openstack share type list` command to get a share type.
Then use the share type to create a share group type.

.. code-block:: console

   $ openstack share type list
   +--------------------------------------+---------------------+------------+------------+--------------------------------------+-----------------------------+
   | ID                                   | Name                | Visibility | Is Default | Required Extra Specs                 | Optional Extra Specs        |
   +--------------------------------------+---------------------+------------+------------+--------------------------------------+-----------------------------+
   | ee6287aa-448b-432b-a928-41ce9d8e149f | default_share_type  | public     | -          | driver_handles_share_servers : False |                             |
   +--------------------------------------+---------------------+------------+------------+--------------------------------------+-----------------------------+

Use the :command:`openstack share group type create` command to create a new
share group type. Specify the name and share types.

.. code-block:: console

   $ openstack share group type create group_type_for_cg default_share_type
   +-------------+--------------------------------------+
   | Field       | Value                                |
   +-------------+--------------------------------------+
   | id          | cfe42f20-d13e-4348-9370-f0763e426db3 |
   | name        | group_type_for_cg                    |
   | share_types | ee6287aa-448b-432b-a928-41ce9d8e149f |
   | visibility  | public                               |
   | is_default  | False                                |
   | group_specs |                                      |
   +-------------+--------------------------------------+

Use the :command:`openstack share group type set` command to set a group-spec to the
share group type.

.. code-block:: console

   $ openstack share group type set group_type_for_cg \
       --group-specs consistent_snapshot_support=host

.. note::
   This command has no output. To verify the group-spec, use the
   :command:`openstack share group type list` command and specify
   the share group type's name or ID as a parameter.

Creating a share group
----------------------

Use the :command:`openstack share group create` command to create a share group.
Specify the share group type that we created.

.. code-block:: console

   $ openstack share group create --share-group-type group_type_for_cg
   +--------------------------------+--------------------------------------+
   | Field                          | Value                                |
   +--------------------------------+--------------------------------------+
   | id                             | ecf78d45-546a-48df-a969-c153e68f0376 |
   | name                           | None                                 |
   | created_at                     | 2026-03-31T02:08:52.799823           |
   | status                         | creating                             |
   | description                    | None                                 |
   | project_id                     | 87ba30b5315c40ec8ec5e3346112eae4     |
   | host                           | None                                 |
   | share_group_type_id            | cfe42f20-d13e-4348-9370-f0763e426db3 |
   | source_share_group_snapshot_id | None                                 |
   | share_network_id               | None                                 |
   | share_types                    | ee6287aa-448b-432b-a928-41ce9d8e149f |
   | availability_zone              | None                                 |
   | consistent_snapshot_support    | None                                 |
   +--------------------------------+--------------------------------------+

.. note::
   One share group can include multiple share types. The share types are going
   to be inherited directly from the share group type.

Use the :command:`openstack share group show` command to retrieve details of the share.
Specify the share ID or name as a parameter.

.. code-block:: console

   $ openstack share group show ecf78d45-546a-48df-a969-c153e68f0376
   +--------------------------------+--------------------------------------+
   | Field                          | Value                                |
   +--------------------------------+--------------------------------------+
   | id                             | ecf78d45-546a-48df-a969-c153e68f0376 |
   | name                           | None                                 |
   | created_at                     | 2026-03-31T02:08:52.988027           |
   | status                         | available                            |
   | description                    | None                                 |
   | project_id                     | 87ba30b5315c40ec8ec5e3346112eae4     |
   | host                           | ubuntu@generic2#test_pool            |
   | share_group_type_id            | cfe42f20-d13e-4348-9370-f0763e426db3 |
   | source_share_group_snapshot_id | None                                 |
   | share_network_id               | None                                 |
   | share_types                    | ee6287aa-448b-432b-a928-41ce9d8e149f |
   | availability_zone              | nova                                 |
   | consistent_snapshot_support    | pool                                 |
   +--------------------------------+--------------------------------------+

Create a share with the share group
-----------------------------------

Use the :command:`openstack share create` command to create a share. Specify the share
protocol, size, share group type and the share name.

.. code-block:: console

   $ openstack share create NFS 1 \
       --share-group ecf78d45-546a-48df-a969-c153e68f0376 \
       --name test_group_share_1
   +---------------------------------------+--------------------------------------+
   | Field                                 | Value                                |
   +---------------------------------------+--------------------------------------+
   | id                                    | 21997eaf-712e-433e-8872-4ff085683657 |
   | size                                  | 1                                    |
   | availability_zone                     | nova                                 |
   | created_at                            | 2026-03-31T02:28:16.192637           |
   | status                                | creating                             |
   | name                                  | test_group_share_1                   |
   | description                           | None                                 |
   | project_id                            | 87ba30b5315c40ec8ec5e3346112eae4     |
   | snapshot_id                           | None                                 |
   | share_network_id                      | None                                 |
   | share_proto                           | NFS                                  |
   | metadata                              | {}                                   |
   | share_type                            | ee6287aa-448b-432b-a928-41ce9d8e149f |
   | is_public                             | False                                |
   | snapshot_support                      | True                                 |
   | task_state                            | None                                 |
   | share_type_name                       | default_share_type                   |
   | access_rules_status                   | active                               |
   | replication_type                      | None                                 |
   | has_replicas                          | False                                |
   | user_id                               | b7f2c522a5644a83b78b3f61f50c6d71     |
   | create_share_from_snapshot_support    | True                                 |
   | revert_to_snapshot_support            | True                                 |
   | share_group_id                        | ecf78d45-546a-48df-a969-c153e68f0376 |
   | source_share_group_snapshot_member_id | None                                 |
   | mount_snapshot_support                | True                                 |
   | progress                              | None                                 |
   +---------------------------------------+--------------------------------------+

Create another share with a same share group, and named 'test_group_share_2'.

.. code-block:: console

   $ openstack share create NFS 1 \
       --share-group ecf78d45-546a-48df-a969-c153e68f0376 \
       --name test_group_share_2
   +---------------------------------------+--------------------------------------+
   | Field                                 | Value                                |
   +---------------------------------------+--------------------------------------+
   | id                                    | 8d34a9a3-3b8c-4771-af2c-66c78fe1e0b1 |
   | size                                  | 1                                    |
   | availability_zone                     | nova                                 |
   | created_at                            | 2026-03-31T21:01:36.784688           |
   | status                                | creating                             |
   | name                                  | test_group_share_2                   |
   | description                           | None                                 |
   | project_id                            | 87ba30b5315c40ec8ec5e3346112eae4     |
   | snapshot_id                           | None                                 |
   | share_network_id                      | None                                 |
   | share_proto                           | NFS                                  |
   | metadata                              | {}                                   |
   | share_type                            | ee6287aa-448b-432b-a928-41ce9d8e149f |
   | is_public                             | False                                |
   | snapshot_support                      | True                                 |
   | task_state                            | None                                 |
   | share_type_name                       | default_share_type                   |
   | access_rules_status                   | active                               |
   | replication_type                      | None                                 |
   | has_replicas                          | False                                |
   | user_id                               | b7f2c522a5644a83b78b3f61f50c6d71     |
   | create_share_from_snapshot_support    | True                                 |
   | revert_to_snapshot_support            | True                                 |
   | share_group_id                        | ecf78d45-546a-48df-a969-c153e68f0376 |
   | source_share_group_snapshot_member_id | None                                 |
   | mount_snapshot_support                | True                                 |
   | progress                              | None                                 |
   +---------------------------------------+--------------------------------------+


Creating a share group snapshot
-------------------------------

Create a share group sanpshot of the share group

Use the :command:`openstack share group snapshot create` command to create a
share group snapshot. Specify the share group ID or name.

.. code-block:: console

   $ openstack share group snapshot create \
       ecf78d45-546a-48df-a969-c153e68f0376
   +----------------+--------------------------------------+
   | Field          | Value                                |
   +----------------+--------------------------------------+
   | id             | ac387240-08dc-4b23-80f6-ffc481e6c87a |
   | name           | None                                 |
   | created_at     | 2026-03-31T21:04:54.276514           |
   | status         | creating                             |
   | description    | None                                 |
   | project_id     | 87ba30b5315c40ec8ec5e3346112eae4     |
   | share_group_id | ecf78d45-546a-48df-a969-c153e68f0376 |
   +----------------+--------------------------------------+

Show the members of the share group snapshot

Use the :command:`openstack share group snapshot show` command to see all
share members of share group snapshot. Specify the share group snapshot
ID or name.

.. code-block:: console

   $ openstack share group snapshot members list \
       ac387240-08dc-4b23-80f6-ffc481e6c87a
   +--------------------------------------+------+
   | Share ID                             | Size |
   +--------------------------------------+------+
   | 21997eaf-712e-433e-8872-4ff085683657 | 1    |
   | 8d34a9a3-3b8c-4771-af2c-66c78fe1e0b1 | 1    |
   +--------------------------------------+------+

Show the details of the share group snapshot

.. code-block:: console

   $ openstack share group snapshot show ac387240-08dc-4b23-80f6-ffc481e6c87a
   +----------------+--------------------------------------+
   | Field          | Value                                |
   +----------------+--------------------------------------+
   | id             | ac387240-08dc-4b23-80f6-ffc481e6c87a |
   | name           | None                                 |
   | created_at     | 2026-03-31T21:04:54.276514           |
   | status         | available                            |
   | description    | None                                 |
   | project_id     | 87ba30b5315c40ec8ec5e3346112eae4     |
   | share_group_id | ecf78d45-546a-48df-a969-c153e68f0376 |
   +----------------+--------------------------------------+

Deleting share groups
---------------------

Use the :command:`openstack share group delete <group_id>`
to delete share groups.

Deleting share group snapshots
------------------------------
Use the :command:`openstack share group snapshot delete <group_snapshot_id>`
to delete share a share group snapshot.

.. important::
    Before attempting to delete a share group or a share group snapshot, make
    sure that all its constituent shares and snapshots were deleted.
    Users will need to delete share group snapshots before attempting to delete
    shares within  ashare group or the group itself.
