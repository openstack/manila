Creating shares with Shared File Systems Option 1 (DHSS = False)
----------------------------------------------------------------

Create a share type
-------------------

Disable DHSS (``driver_handles_share_servers``) before creating a share using
the LVM driver.

#. Source the admin credentials to gain access to admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. Create a default share type with DHSS disabled. A default share type will
   allow you to create shares with this driver, without having to specify
   the share type explicitly during share creation.

   .. code-block:: console

      $ manila type-create default_share_type False
      +----------------------+--------------------------------------+
      | Property             | Value                                |
      +----------------------+--------------------------------------+
      | required_extra_specs | driver_handles_share_servers : False |
      | Name                 | default_share_type                   |
      | Visibility           | public                               |
      | is_default           | -                                    |
      | ID                   | 3df065c8-6ca4-4b80-a5cb-e633c0439097 |
      | optional_extra_specs | snapshot_support : True              |
      +----------------------+--------------------------------------+

   Set this default share type in ``manila.conf`` under the ``[DEFAULT]``
   section and restart the ``manila-api`` service before proceeding.
   Unless you do so, the default share type will not be effective.

   .. note::

      Creating and configuring a default share type is optional. If you wish
      to use the shared file system service with a variety of share types,
      where each share creation request could specify a type, please refer to
      the Share types usage documentation `here
      <https://docs.openstack.org/manila/latest/admin/shared-file-systems-share-types.html>`_.

Create a share
--------------

#. Source the ``demo`` credentials to perform
   the following steps as a non-administrative project:

   .. code-block:: console

      $ . demo-openrc

#. Create an NFS share. Since a default share type has been created and
   configured, it need not be specified in the request.

   .. code-block:: console

      $ manila create NFS 1 --name share1
      +-----------------------------+--------------------------------------+
      | Property                    | Value                                |
      +-----------------------------+--------------------------------------+
      | status                      | creating                             |
      | share_type_name             | default_share_type                   |
      | description                 | None                                 |
      | availability_zone           | None                                 |
      | share_network_id            | None                                 |
      | share_group_id              | None                                 |
      | host                        |                                      |
      | access_rules_status         | active                               |
      | snapshot_id                 | None                                 |
      | is_public                   | False                                |
      | task_state                  | None                                 |
      | snapshot_support            | True                                 |
      | id                          | 55c401b3-3112-4294-aa9f-3cc355a4e361 |
      | size                        | 1                                    |
      | name                        | share1                               |
      | share_type                  | 3df065c8-6ca4-4b80-a5cb-e633c0439097 |
      | has_replicas                | False                                |
      | replication_type            | None                                 |
      | created_at                  | 2016-03-30T19:10:33.000000           |
      | share_proto                 | NFS                                  |
      | project_id                  | 3a46a53a377642a284e1d12efabb3b5a     |
      | metadata                    | {}                                   |
      +-----------------------------+--------------------------------------+

#. After some time, the share status should change from ``creating``
   to ``available``:

   .. code-block:: console

      $ manila list
      +--------------------------------------+--------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+
      | ID                                   | Name   | Size | Share Proto | Status    | Is Public | Share Type Name    | Host                        | Availability Zone |
      +--------------------------------------+--------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+
      | 55c401b3-3112-4294-aa9f-3cc355a4e361 | share1 | 1    | NFS         | available | False     | default_share_type | storage@lvm#lvm-single-pool | nova              |
      +--------------------------------------+--------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+

#. Determine export IP address of the share:

   .. code-block:: console

      $ manila show share1
      +-----------------------------+------------------------------------------------------------------------------------+
      | Property                    | Value                                                                              |
      +-----------------------------+------------------------------------------------------------------------------------+
      | status                      | available                                                                          |
      | share_type_name             | default_share_type                                                                 |
      | description                 | None                                                                               |
      | availability_zone           | nova                                                                               |
      | share_network_id            | None                                                                               |
      | share_group_id              | None                                                                               |
      | export_locations            |                                                                                    |
      |                             | path = 10.0.0.41:/var/lib/manila/mnt/share-8e13a98f-c310-41df-ac90-fc8bce4910b8    |
      |                             | id = 3c8d0ada-cadf-48dd-85b8-d4e8c3b1e204                                          |
      |                             | preferred = False                                                                  |
      | host                        | storage@lvm#lvm-single-pool                                                        |
      | access_rules_status         | active                                                                             |
      | snapshot_id                 | None                                                                               |
      | is_public                   | False                                                                              |
      | task_state                  | None                                                                               |
      | snapshot_support            | True                                                                               |
      | id                          | 55c401b3-3112-4294-aa9f-3cc355a4e361                                               |
      | size                        | 1                                                                                  |
      | name                        | share1                                                                             |
      | share_type                  | c6dfcfc6-9920-420e-8b0a-283d578efef5                                               |
      | has_replicas                | False                                                                              |
      | replication_type            | None                                                                               |
      | created_at                  | 2016-03-30T19:10:33.000000                                                         |
      | share_proto                 | NFS                                                                                |
      | project_id                  | 3a46a53a377642a284e1d12efabb3b5a                                                   |
      | metadata                    | {}                                                                                 |
      +-----------------------------+------------------------------------------------------------------------------------+

Allow access to the share
-------------------------

#. Configure access to the new share before attempting to mount it via
   the network. The compute instance (whose IP address is referenced by the
   INSTANCE_IP below) must have network connectivity to the network specified
   in the share network.

   .. code-block:: console

      $ manila access-allow share1 ip INSTANCE_IP
      +--------------+--------------------------------------+
      | Property     | Value                                |
      +--------------+--------------------------------------+
      | share_id     | 55c401b3-3112-4294-aa9f-3cc355a4e361 |
      | access_type  | ip                                   |
      | access_to    | 10.0.0.46                            |
      | access_level | rw                                   |
      | state        | new                                  |
      | id           | f88eab01-7197-44bf-ad0f-d6ca6f99fc96 |
      +--------------+--------------------------------------+

Mount the share on a compute instance
-------------------------------------

#. Log into your compute instance and create a folder where the mount will
   be placed:

   .. code-block:: console

      $ mkdir ~/test_folder

#. Mount the NFS share in the compute instance using the export location of
   the share:

   .. code-block:: console

      # mount -vt nfs 10.0.0.41:/var/lib/manila/mnt/share-8e13a98f-c310-41df-ac90-fc8bce4910b8 ~/test_folder
