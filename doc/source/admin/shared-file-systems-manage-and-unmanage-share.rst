.. _shared_file_systems_manage_and_unmanage_share:

=========================
Manage and unmanage share
=========================

To ``manage`` a share means that an administrator, rather than a share
driver, manages the storage lifecycle. This approach is appropriate when an
administrator already has the custom non-manila share with its size, shared
file system protocol, and export path, and an administrator wants to
register it in the Shared File System service.

To ``unmanage`` a share means to unregister a specified share from the Shared
File Systems service. Administrators can revert an unmanaged share to managed
status if needed.

.. _unmanage_share:

Unmanage a share
----------------

.. note::

    The ``unmanage`` operation is not supported for shares that were created on
    top of share servers and created with share networks until Shared File
    Systems API version ``2.49`` (Stein/Manila 8.0.0 release).

.. important::

    Shares that have dependent snapshots or share replicas cannot be removed
    from the Shared File Systems service unless the snapshots have been removed
    or unmanaged and the share replicas have been removed.

Unmanaging a share removes it from the management of the Shared File Systems
service without deleting the share. It is a non-disruptive operation and
existing clients are not disconnected, and the functionality is aimed at aiding
infrastructure operations and maintenance workflows. To unmanage a share,
run the :command:`openstack share abandon` command. Then try to print
the information about the share. The returned result should indicate that
Shared File Systems service won't
find the share:

.. code-block:: console

   $ openstack share abandon share_for_docs
   $ openstack share show share_for_docs
   ERROR: No share with a name or ID of 'share_for_docs' exists.

.. _manage_share:

Manage a share
--------------
.. note::
    The ``manage`` operation is not supported for shares that are exported on
    share servers via share networks until Shared File Systems API version
    ``2.49`` (Stein/Manila 8.0.0 release).

.. note::
    From API version 2.53, if the requester specifies a share type containing
    a ``replication_type`` extra spec while managing a share, manila quota
    system will reserve and consume resources for two additional quotas:
    ``share_replicas`` and ``replica_gigabytes``.
    From API version 2.62, manila quota system will validate size of the
    share against ``per_share_gigabytes`` quota.

To register the non-managed share in the File System service, run the
:command:`openstack share adopt` command:

.. code-block:: console

   openstack share adopt [-h] [-f {json,shell,table,value,yaml}]
                         [-c COLUMN] [--noindent] [--prefix PREFIX]
                         [--max-width <integer>] [--fit-width]
                         [--print-empty] [--name <name>]
                         [--description <description>]
                         [--share-type <share-type>]
                         [--driver-options [<key=value> ...]]
                         [--public]
                         [--share-server-id <share-server-id>]
                         [--wait]
                         <service-host> <protocol> <export-path>

The positional arguments are:

- service_host. The manage-share service host in
  ``host@backend#POOL`` format, which consists of the host name for
  the back end, the name of the back end, and the pool name for the
  back end.

- protocol. The Shared File Systems protocol of the share to manage. Valid
  values are NFS, CIFS, GlusterFS, HDFS or MAPRFS.

- export_path. The share export path in the format appropriate for the
  protocol:

  - NFS protocol. 10.0.0.1:/foo_path.

  - CIFS protocol. \\\\10.0.0.1\\foo_name_of_cifs_share.

  - HDFS protocol. hdfs://10.0.0.1:foo_port/foo_share_name.

  - GlusterFS. 10.0.0.1:/foo_volume.

  - MAPRFS. maprfs:///share-0 -C  -Z  -N foo.

The optional arguments are:

- name. The name of the share that is being managed.

- share_type. The share type of the share that is being managed. If not
  specified, the service will try to manage the share with the configured
  default share type.

- share_server_id. must be provided to manage shares within share networks.
  This argument can only be used with File Systems API version ``2.49``
  (Stein/Manila 8.0.0 release) and beyond.

- driver_options. An optional set of one or more key and value pairs that
  describe driver options. As a result, a special share type named
  ``for_managing`` was used in example.

To manage share, run:

.. code-block:: console

   $ openstack share adopt \
    manila@saopaulo#shares \
    nfs \
    10.0.0.10:/shares/share_e113729a_8da4_45f3_bbbf_0014f_350380c_c4b06060_9c56_459e_9219_b86a0777054b \
    --name share_for_docs \
    --description "We manage share." \
    --share-type default

   +-------------------------------------+--------------------------------------+
   | Field                               | Value                                |
   +-------------------------------------+--------------------------------------+
   | id                                  | 8b3aa39d-e07f-4255-82ac-f6f56565a725 |
   | size                                | None                                 |
   | availability_zone                   | None                                 |
   | created_at                          | 2025-04-03T10:57:19.230793           |
   | status                              | manage_starting                      |
   | name                                | share_for_docs                       |
   | description                         | We manage share.                     |
   | project_id                          | c0bc204890ad428796f364b677a8516b     |
   | snapshot_id                         | None                                 |
   | share_network_id                    | None                                 |
   | share_proto                         | NFS                                  |
   | metadata                            | {}                                   |
   | share_type                          | 807e5cd7-a0e7-4912-8f7d-352512ce51c3 |
   | volume_type                         | default                              |
   | is_public                           | False                                |
   | snapshot_support                    | True                                 |
   | task_state                          | None                                 |
   | share_type_name                     | default                              |
   | access_rules_status                 | active                               |
   | replication_type                    | None                                 |
   | has_replicas                        | False                                |
   | user_id                             | c5d0c19aae6e4484a41e241f0d8b04fb     |
   | create_share_from_snapshot_support  | True                                 |
   | revert_to_snapshot_support          | True                                 |
   | share_group_id                      | None                                 |
   | source_share_group_snapshot_member_ | None                                 |
   | id                                  |                                      |
   | mount_snapshot_support              | True                                 |
   | progress                            | None                                 |
   | is_soft_deleted                     | False                                |
   | scheduled_to_be_deleted_at          | None                                 |
   | source_backup_id                    | None                                 |
   | share_server_id                     | None                                 |
   | host                                | manila@saopaulo#shares               |
   +-------------------------------------+--------------------------------------+

Check that the share is available:

.. code-block:: console

   $ openstack share show share_for_docs
   +-------------------------------------+--------------------------------------+
   | Field                               | Value                                |
   +-------------------------------------+--------------------------------------+
   | id                                  | 8b3aa39d-e07f-4255-82ac-f6f56565a725 |
   | size                                | 1                                    |
   | availability_zone                   | manila-zone-1                        |
   | created_at                          | 2025-04-03T10:57:19.230793           |
   | status                              | available                            |
   | name                                | share_for_docs                       |
   | description                         | We manage share.                     |
   | project_id                          | c0bc204890ad428796f364b677a8516b     |
   | snapshot_id                         | None                                 |
   | share_network_id                    | None                                 |
   | share_proto                         | NFS                                  |
   | share_type                          | 807e5cd7-a0e7-4912-8f7d-352512ce51c3 |
   | volume_type                         | default                              |
   | is_public                           | False                                |
   | snapshot_support                    | True                                 |
   | task_state                          | None                                 |
   | share_type_name                     | default                              |
   | access_rules_status                 | active                               |
   | replication_type                    | None                                 |
   | has_replicas                        | False                                |
   | user_id                             | c5d0c19aae6e4484a41e241f0d8b04fb     |
   | create_share_from_snapshot_support  | True                                 |
   | revert_to_snapshot_support          | True                                 |
   | share_group_id                      | None                                 |
   | source_share_group_snapshot_member_ | None                                 |
   | id                                  |                                      |
   | mount_snapshot_support              | True                                 |
   | progress                            | 100%                                 |
   | is_soft_deleted                     | False                                |
   | scheduled_to_be_deleted_at          | None                                 |
   | source_backup_id                    | None                                 |
   | share_server_id                     | None                                 |
   | host                                | manila@saopaulo#shares               |
   | export_locations                    |                                      |
   |                                     | id =                                 |
   |                                     | ba4ad0cd-6d25-422f-97f6-a1bc383ae49d |
   |                                     | path = 11.0.0.11:/shares/share_e1137 |
   |                                     | 29a_8da4_45f3_bbbf_0014f350380c_c4b0 |
   |                                     | 6060_9c56_459e_9219_b86a0777054b     |
   |                                     | preferred = False                    |
   |                                     | metadata = {}                        |
   |                                     | share_instance_id =                  |
   |                                     | c4b06060-9c56-459e-9219-b86a0777054b |
   |                                     | is_admin_only = True                 |
   |                                     | id =                                 |
   |                                     | c525a3aa-b52a-4565-acf3-aacaca1167ec |
   |                                     | path = 10.0.0.10:/shares/share_e1137 |
   |                                     | 29a_8da4_45f3_bbbf_0014f350380c_c4b0 |
   |                                     | 6060_9c56_459e_9219_b86a0777054b     |
   |                                     | preferred = True                     |
   |                                     | metadata = {}                        |
   |                                     | share_instance_id =                  |
   |                                     | c4b06060-9c56-459e-9219-b86a0777054b |
   |                                     | is_admin_only = False                |
   |                                     | id =                                 |
   |                                     | b5c26041-eba0-415d-8bda-f46ca67a55b9 |
   |                                     | path = 10.0.0.20:/shares/share_e1137 |
   |                                     | 29a_8da4_45f3_bbbf_0014f350380c_c4b0 |
   |                                     | 6060_9c56_459e_9219_b86a0777054b     |
   |                                     | preferred = False                    |
   |                                     | metadata = {}                        |
   |                                     | share_instance_id =                  |
   |                                     | c4b06060-9c56-459e-9219-b86a0777054b |
   |                                     | is_admin_only = False                |
   | properties                          |                                      |
   +-------------------------------------+--------------------------------------+
