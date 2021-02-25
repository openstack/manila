.. _shared_file_systems_profiling:

==========================================
Profiling the Shared File Systems service
==========================================

Profiler
^^^^^^^^

The detailed description of the profiler and its config options is available at
`Profiler docs <https://docs.openstack.org/osprofiler/latest/user/index.html>`_.


Using Profiler
^^^^^^^^^^^^^^

To start profiling Manila code, the following steps have to be taken:

#. Add the following lines to the ``/etc/manila/manila.conf`` file (the
   profiling is disabled by default).

   .. code-block:: console

      [profiler]
      connection_string = redis://localhost:6379
      hmac_keys = SECRET_KEY
      trace_sqlalchemy = True
      enabled = True

   Examples of possible values for ``connection_string`` option:

   * ``messaging://`` - use oslo_messaging driver for sending spans.
   * ``redis://127.0.0.1:6379`` - use redis driver for sending spans.
   * ``mongodb://127.0.0.1:27017`` - use mongodb driver for sending spans.
   * ``elasticsearch://127.0.0.1:9200`` - use elasticsearch driver for sending spans.
   * ``jaeger://127.0.0.1:6831`` - use jaeger tracing as driver for sending spans.

#. Restart all manila services and keystone service.

#. To verify profiler with manilaclient, run any command with ``--profile <key>.``
   The key (e.g. SECRET_KEY) should be one of the ``hmac_keys`` mentioned in
   manila.conf. To generate correct profiling information across all services
   at least one key needs to be consistent between OpenStack projects.

   .. code-block:: console

       $ manila --profile SECRET_KEY create NFS 1 --name Share1 --share-network testNetwork --share-type dhss_true
        +---------------------------------------+--------------------------------------+
        | Property                              | Value                                |
        +---------------------------------------+--------------------------------------+
        | id                                    | 9703da88-25ba-41e6-827d-a6932f708dd4 |
        | size                                  | 1                                    |
        | availability_zone                     | None                                 |
        | created_at                            | 2021-02-23T11:21:38.000000           |
        | status                                | creating                             |
        | name                                  | Share1                               |
        | description                           | None                                 |
        | project_id                            | c67b2fd35b054060971d28cf654ee92a     |
        | snapshot_id                           | None                                 |
        | share_network_id                      | 03754c58-1456-497f-b7d6-8f36a4d644f0 |
        | share_proto                           | NFS                                  |
        | metadata                              | {}                                   |
        | share_type                            | 5b1a4133-371c-4583-a801-f2b6e1ae102d |
        | is_public                             | False                                |
        | snapshot_support                      | False                                |
        | task_state                            | None                                 |
        | share_type_name                       | dhss_true                            |
        | access_rules_status                   | active                               |
        | replication_type                      | None                                 |
        | has_replicas                          | False                                |
        | user_id                               | 7ecd60ddae1448b79449dc6434460eaf     |
        | create_share_from_snapshot_support    | False                                |
        | revert_to_snapshot_support            | False                                |
        | share_group_id                        | None                                 |
        | source_share_group_snapshot_member_id | None                                 |
        | mount_snapshot_support                | False                                |
        | progress                              | None                                 |
        | share_server_id                       | None                                 |
        | host                                  |                                      |
        +---------------------------------------+--------------------------------------+
        Profiling trace ID: 1705dfd8-e45a-46cd-b0e2-2e40fd9e5f22
        To display trace use next command:
        osprofiler trace show --html 1705dfd8-e45a-46cd-b0e2-2e40fd9e5f22

#. To verify profiler with openstackclient, run any command with
   ``--os-profile <key>``.

   .. code-block:: console

       $ openstack --os-profile SECRET_KEY share create NFS 1 --name Share2 --share-network testNetwork --share-type dhss_true
        +---------------------------------------+--------------------------------------+
        | Field                                 | Value                                |
        +---------------------------------------+--------------------------------------+
        | access_rules_status                   | active                               |
        | availability_zone                     | None                                 |
        | create_share_from_snapshot_support    | False                                |
        | created_at                            | 2021-02-23T11:23:41.000000           |
        | description                           | None                                 |
        | has_replicas                          | False                                |
        | host                                  |                                      |
        | id                                    | 78a19734-394f-4967-9671-c226df00a023 |
        | is_public                             | False                                |
        | metadata                              | {}                                   |
        | mount_snapshot_support                | False                                |
        | name                                  | Share2                               |
        | progress                              | None                                 |
        | project_id                            | c67b2fd35b054060971d28cf654ee92a     |
        | replication_type                      | None                                 |
        | revert_to_snapshot_support            | False                                |
        | share_group_id                        | None                                 |
        | share_network_id                      | 03754c58-1456-497f-b7d6-8f36a4d644f0 |
        | share_proto                           | NFS                                  |
        | share_server_id                       | None                                 |
        | share_type                            | 5b1a4133-371c-4583-a801-f2b6e1ae102d |
        | share_type_name                       | dhss_true                            |
        | size                                  | 1                                    |
        | snapshot_id                           | None                                 |
        | snapshot_support                      | False                                |
        | source_share_group_snapshot_member_id | None                                 |
        | status                                | creating                             |
        | task_state                            | None                                 |
        | user_id                               | 7ecd60ddae1448b79449dc6434460eaf     |
        | volume_type                           | dhss_true                            |
        +---------------------------------------+--------------------------------------+
        Trace ID: 0ca7ce01-36a9-481c-8b3d-263a3b5caa35
        Short trace ID for OpenTracing-based drivers: 8b3d263a3b5caa35
        Display trace data with command:
        osprofiler trace show --html 0ca7ce01-36a9-481c-8b3d-263a3b5caa35

#. To display the trace date in HTML format, run below command.

   .. code-block:: console

       $ osprofiler trace show --html 0ca7ce01-36a9-481c-8b3d-263a3b5caa35 --connection-string redis://localhost:6379 --out /opt/stack/output.html

