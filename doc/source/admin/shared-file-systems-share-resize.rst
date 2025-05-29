.. _shared_file_systems_share_resize:

============
Resize share
============

For most drivers, resizing the share is safe operation. If you want to be sure
that your data is safe, you can make a share back up by creating a snapshot of
it.

You can extend and shrink the share with the :command:`openstack share resize`
command, and specify the share with the new size that does not exceed the
quota. For details, see :ref:`Quotas and Limits <shared_file_systems_quotas>`.
You also cannot shrink share size to 0 or to a greater value than the current
share size.

.. note::
    From API version 2.53, extending a replicated share, manila quota system
    will reserve and consume resources for two additional quotas:
    ``share_replicas`` and ``replica_gigabytes``. This request will fail if
    there is no available quotas to extend the share and all of its share
    replicas.


While extending, the share has an ``extending`` status. This means that
the increase share size request was issued successfully.

To extend the share and check the result, run:

.. code-block:: console

   $ openstack share resize docs_resize 2
   $ openstack share show docs_resize
   +---------------------------------------+---------------------------------------+
   | Property                              | Value                                 |
   +---------------------------------------+---------------------------------------+
   | id                                    | a3454cf1-bb1d-4e4d-a8e4-a3881c593720  |
   | size                                  | 2                                     |
   | availability_zone                     | manila-zone-0                         |
   | created_at                            | 2024-09-26T14:53:18.153832            |
   | status                                | extending                             |
   | name                                  | docs_resize                           |
   | description                           | None                                  |
   | project_id                            | 1f31ee1c3e3c443bbf9aee5684456daa      |
   | snapshot_id                           | None                                  |
   | share_network_id                      | None                                  |
   | share_proto                           | NFS                                   |
   | metadata                              | {}                                    |
   | share_type                            | 303f0a73-711e-4beb-a4f7-a60acc1d588e  |
   | is_public                             | True                                  |
   | snapshot_support                      | True                                  |
   | task_state                            | None                                  |
   | share_type_name                       | default                               |
   | access_rules_status                   | active                                |
   | replication_type                      | None                                  |
   | has_replicas                          | False                                 |
   | user_id                               | b47d81c8c8c74ea3a7c13461f30ad5ed      |
   | create_share_from_snapshot_support    | True                                  |
   | revert_to_snapshot_support            | False                                 |
   | share_group_id                        | None                                  |
   | source_share_group_snapshot_member_id | None                                  |
   | mount_snapshot_support                | False                                 |
   | progress                              | 100%                                  |
   | is_soft_deleted                       | False                                 |
   | scheduled_to_be_deleted_at            | None                                  |
   | source_backup_id                      | None                                  |
   | share_server_id                       | None                                  |
   | host                                  | host@backend1#poolA                   |
   +---------------------------------------+---------------------------------------+

While shrinking, the share has a ``shrinking`` status. This means that the
decrease share size request was issued successfully. To shrink the share and
check the result, run:

.. code-block:: console

   $ openstack share resize docs_resize 1
   $ openstack share show docs_resize
   +---------------------------------------+---------------------------------------+
   | Property                              | Value                                 |
   +---------------------------------------+---------------------------------------+
   | id                                    | a3454cf1-bb1d-4e4d-a8e4-a3881c593720  |
   | size                                  | 1                                     |
   | availability_zone                     | manila-zone-0                         |
   | created_at                            | 2024-09-26T14:53:18.153832            |
   | status                                | shrinking                             |
   | name                                  | docs_resize                           |
   | description                           | None                                  |
   | project_id                            | 1f31ee1c3e3c443bbf9aee5684456daa      |
   | snapshot_id                           | None                                  |
   | share_network_id                      | None                                  |
   | share_proto                           | NFS                                   |
   | metadata                              | {'__mount_options': 'fs=cephfs'}      |
   | share_type                            | 303f0a73-711e-4beb-a4f7-a60acc1d588e  |
   | is_public                             | True                                  |
   | snapshot_support                      | True                                  |
   | task_state                            | None                                  |
   | share_type_name                       | default                               |
   | access_rules_status                   | active                                |
   | replication_type                      | None                                  |
   | has_replicas                          | False                                 |
   | user_id                               | b47d81c8c8c74ea3a7c13461f30ad5ed      |
   | create_share_from_snapshot_support    | True                                  |
   | revert_to_snapshot_support            | False                                 |
   | share_group_id                        | None                                  |
   | source_share_group_snapshot_member_id | None                                  |
   | mount_snapshot_support                | False                                 |
   | progress                              | 100%                                  |
   | is_soft_deleted                       | False                                 |
   | scheduled_to_be_deleted_at            | None                                  |
   | source_backup_id                      | None                                  |
   | share_server_id                       | None                                  |
   | host                                  | host@backend1#poolA                   |
   +---------------------------------------+---------------------------------------+
