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

      $ openstack share type create default_share_type False
      +----------------------+--------------------------------------+
      | Field                | Value                                |
      +----------------------+--------------------------------------+
      | id                   | 0e47e06e-7888-4a42-9a09-7ad56cc71472 |
      | name                 | default_share_type                   |
      | visibility           | public                               |
      | is_default           | -                                    |
      | required_extra_specs | driver_handles_share_servers : False |
      | optional_extra_specs | snapshot_support : True              |
      | description          | None                                 |
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

      $ openstack share create NFS 1 --name share1
      +---------------------------------------+--------------------------------------+
      | Field                                 | Value                                |
      +---------------------------------------+--------------------------------------+
      | id                                    | 4af6bef6-9c52-4462-b141-d1ed123aedf7 |
      | size                                  | 1                                    |
      | availability_zone                     | None                                 |
      | created_at                            | 2026-03-31T19:10:33.230734           |
      | status                                | creating                             |
      | name                                  | share1                               |
      | description                           | None                                 |
      | project_id                            | 3a46a53a377642a284e1d12efabb3b5a     |
      | snapshot_id                           | None                                 |
      | share_network_id                      | None                                 |
      | share_proto                           | NFS                                  |
      | metadata                              | {}                                   |
      | share_type                            | 0e47e06e-7888-4a42-9a09-7ad56cc71472 |
      | is_public                             | False                                |
      | snapshot_support                      | True                                 |
      | task_state                            | None                                 |
      | share_type_name                       | default_share_type                   |
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

#. After some time, the share status should change from ``creating``
   to ``available``:

   .. code-block:: console

      $ openstack share list
      +--------------------------------------+--------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+
      | ID                                   | Name   | Size | Share Proto | Status    | Is Public | Share Type Name    | Host                        | Availability Zone |
      +--------------------------------------+--------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+
      | 4af6bef6-9c52-4462-b141-d1ed123aedf7 | share1 |    1 | NFS         | available | False     | default_share_type | storage@lvm#lvm-single-pool | nova              |
      +--------------------------------------+--------+------+-------------+-----------+-----------+--------------------+-----------------------------+-------------------+

#. Determine export IP address of the share:

   .. code-block:: console

      $ openstack share show share1
      +---------------------------------------+--------------------------------------------------------------------+
      | Field                                 | Value                                                              |
      +---------------------------------------+--------------------------------------------------------------------+
      | id                                    | 4af6bef6-9c52-4462-b141-d1ed123aedf7                               |
      | size                                  | 1                                                                  |
      | availability_zone                     | nova                                                               |
      | created_at                            | 2026-03-31T19:10:33.230734                                         |
      | status                                | available                                                          |
      | name                                  | share1                                                             |
      | description                           | None                                                               |
      | project_id                            | 3a46a53a377642a284e1d12efabb3b5a                                   |
      | snapshot_id                           | None                                                               |
      | share_network_id                      | None                                                               |
      | share_proto                           | NFS                                                                |
      | share_type                            | 0e47e06e-7888-4a42-9a09-7ad56cc71472                               |
      | is_public                             | False                                                              |
      | snapshot_support                      | True                                                               |
      | task_state                            | None                                                               |
      | share_type_name                       | default_share_type                                                 |
      | access_rules_status                   | active                                                             |
      | replication_type                      | None                                                               |
      | has_replicas                          | False                                                              |
      | user_id                               | a6c6f585fe5249cbb91426b37e1161a7                                   |
      | create_share_from_snapshot_support    | True                                                               |
      | revert_to_snapshot_support            | True                                                               |
      | share_group_id                        | None                                                               |
      | source_share_group_snapshot_member_id | None                                                               |
      | mount_snapshot_support                | True                                                               |
      | progress                              | 100%                                                               |
      | export_locations                      |                                                                    |
      |                                       | id = 4fecce2c-e297-4823-afa1-3cf3de1a5279                          |
      |                                       | path = 192.0.2.41:/sharevolumes/share_4af6bef6_9c52_4462_b141_d1ed |
      |                                       | preferred = True                                                   |
      | properties                            |                                                                    |
      +---------------------------------------+--------------------------------------------------------------------+

Allow access to the share
-------------------------

#. Configure access to the new share before attempting to mount it via
   the network. The compute instance (whose IP address is referenced by the
   INSTANCE_IP below) must have network connectivity to the network specified
   in the share network.

   .. code-block:: console

      $ openstack share access create share1 ip INSTANCE_IP
      +--------------+--------------------------------------+
      | Field        | Value                                |
      +--------------+--------------------------------------+
      | id           | d2426512-4d86-4c3c-8fa7-11c8c7f9c188 |
      | share_id     | 4af6bef6-9c52-4462-b141-d1ed123aedf7 |
      | access_level | rw                                   |
      | access_to    | 198.51.100.46                        |
      | access_type  | ip                                   |
      | state        | queued_to_apply                      |
      | access_key   | None                                 |
      | created_at   | 2026-03-31T19:11:03.430597           |
      | updated_at   | None                                 |
      | properties   |                                      |
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

      # mount -vt nfs \
          192.0.2.41:/sharevolumes/share_4af6bef6_9c52_4462_b141_d1ed123aedf7 \
          ~/test_folder
