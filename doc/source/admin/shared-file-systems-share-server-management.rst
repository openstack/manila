.. _shared_file_systems_share_server_management:

=============
Share servers
=============

A share server is a resource created by the Shared File Systems service when
the driver is operating in the `driver_handles_share_servers = True` mode.
A share server exports users' shares, manages their exports and access rules.

Share servers are abstracted away from end users. Drivers operating in
`driver_handles_share_servers = True` mode manage the lifecycle of these share
servers automatically. Administrators can however remove the share servers from
the management of the Shared File Systems service without destroying them. They
can also bring in existing share servers under the Shared File Systems service.
They can list all available share servers and update their status attribute.
They can delete an specific share server if it has no dependent shares.

=======================
Share server management
=======================

To ``manage`` a share server means that when the driver is operating in the
``driver_handles_share_servers = True`` mode, the administrator can bring a
pre-existing share server under the management of the Shared File Systems
service.

To ``unmanage`` means that the administrator is able to unregister an existing
share server from the Shared File Systems service without deleting it from the
storage back end. To be unmanaged, the referred share server cannot have any
shares known to the Shared File Systems service.

Manage a share server
---------------------
To bring a share server under the Shared File System service, use the
:command:`manila share-server-manage` command:

.. code-block:: console

    manila share-server-manage
        [--driver_options [<key=value> [<key=value> ...]]]
        [--share_network_subnet <share-network-subnet>]]
        <host> <share_network> <identifier>

The positional arguments are:

- host. The manage-share service host in ``host@backend`` format, which
  consists of the host name for the back end and the name of the back end.

- share_network. The share network where the share server is contained.

- identifier. The identifier of the share server on the back end storage.

The ``driver_options`` is an optional set of one or more driver-specific
metadata items as key and value pairs. The specific key-value pairs necessary
vary from driver to driver. Consult the driver-specific documentation to
determine if any specific parameters must be supplied. Ensure that the share
type has the ``driver_handles_share_servers = True`` extra-spec.

The ``share_network_subnet`` is an optional parameter which was introduced in
Train release. Due to a change in the share networks structure, a share
network no longer contains the following attributes: ``neutron_net_id``,
``neutron_subnet_id``, ``gateway``, ``mtu``, ``network_type``, ``ip_version``,
``segmentation_id``. These attributes now pertain to the share network subnet
entity, and a share network can span multiple share network subnets in
different availability zones. If you do not specify a share network subnet,
the Shared File Systems Service will choose the default one (which does not
pertain to any availability zone).

If using an OpenStack Networking (Neutron) based plugin, ensure that:

- There are some ports created, which correspond to the share server
  interfaces.

- The correct IP addresses are allocated to these ports.

- ``manila:share`` is set as the owner of these ports.

To manage a share server, run:

.. code-block:: console

    $ manila share-server-manage \
        manila@paris \
        share_net_test \
        backend_server_1 \
    +--------------------+------------------------------------------+
    | Property           | Value                                    |
    +--------------------+------------------------------------------+
    | id                 | 441d806f-f0e0-4c90-b7e2-a553c6aa76b2     |
    | project_id         | 907004508ef4447397ce6741a8f037c1         |
    | updated_at         | None                                     |
    | status             | manage_starting                          |
    | host               | manila@paris                             |
    | share_network_name | share_net_test                           |
    | share_network_id   | c895fe26-92be-4152-9e6c-f2ad230efb13     |
    | created_at         | 2019-04-25T18:25:23.000000               |
    | backend_details    | {}                                       |
    | is_auto_deletable  | False                                    |
    | identifier         | backend_server_1                         |
    +--------------------+------------------------------------------+

.. note::

    The ``is_auto_deletable`` property is used by the Shared File Systems
    service to identify a share server that can be deleted by internal
    routines.

    The service can automatically delete share servers if there are no
    shares associated with them. To delete a share server when the last
    share is deleted, set the option: ``delete_share_server_with_last_share``.
    If a scheduled cleanup is desired instead,
    ``automatic_share_server_cleanup`` and
    ``unused_share_server_cleanup_interval`` options can be set. Only one of
    the cleanup methods can be used at one time.

    Any share server that has a share unmanaged from it cannot be
    automatically deleted by the Shared File Systems service. The same is true
    for share servers that have been managed into the service. Cloud
    administrators can delete such share servers manually if desired.

Unmanage a share server
-----------------------

To ``unmanage`` a share server, run
:command:`manila share-server-unmanage <share-server>`.

.. code-block:: console

    $ manila share-server-unmanage 441d806f-f0e0-4c90-b7e2-a553c6aa76b2
    $ manila share-server-show 441d806f-f0e0-4c90-b7e2-a553c6aa76b2
    ERROR: Share server 441d806f-f0e0-4c90-b7e2-a553c6aa76b2 could not be
    found.

Reset the share server state
----------------------------

As administrator you are able to reset a share server state. To reset the state
of a share server, run
:command:`manila share-server-reset-state <share-server> --state <state>`.

The positional arguments are:

- share-server. The share server name or id.

- state. The state to be assigned to the share server. The options are:
    - ``active``
    - ``error``
    - ``deleting``
    - ``creating``
    - ``managing``
    - ``unmanaging``
    - ``unmanage_error``
    - ``manage_error``

List share servers
------------------

To list share servers, run
:command:`manila share-server-list` command:

.. code-block:: console

    manila share-server-list [--host <hostname>] [--status <status>]
                             [--share-network <share_network>]
                             [--project-id <project_id>]
                             [--columns <columns>]

All the arguments above are optional. They can ben used to filter share
servers. The options to filter:

- host. Shows all the share servers pertaining to the specified host.

- status. Shows all the share servers that are in the specified status.

- share_network. Shows all the share servers that pertain in the same share
  network.

- project_id. Shows all the share servers pertaining to the same project.

- columns. The administrator specifies which columns to display in the result
  of the list operation.

.. code-block:: console

    $ manila share-server-list
    +--------------------------------------+--------------+--------+----------------+----------------------------------+------------+
    | Id                                   | Host         | Status | Share Network  | Project Id                       | Updated_at |
    +--------------------------------------+--------------+--------+----------------+----------------------------------+------------+
    | 441d806f-f0e0-4c90-b7e2-a553c6aa76b2 | manila@paris | active | share_net_test | fd6d30efa5ff4c99834dc0d13f96e8eb | None       |
    +--------------------------------------+--------------+--------+----------------+----------------------------------+------------+

===========================================
Share server limits (Since Wallaby release)
===========================================

Since Wallaby release, it is possible to specify limits for share servers size
and amount of instances. It helps administrators to provision their resources
in the cloud system and balance the share servers' size.
If a value is not configured, there is no behavioral change and manila will
consider it as unlimited. Then, will reuse share servers regardless
their size and amount of built instances.

- ``max_share_server_size``: Maximum sum of gigabytes a share server can have
  considering all its share instances and snapshots.

- ``max_shares_per_share_server``: Maximum number of share instances created
  in a share server.

.. note::
   If one of these limits is reached during a request that requires a share
   server to be provided, manila will create a new share server to place such
   request.

.. note::
   The limits can be ignored when placing a new share created from parent
   snapshot in the same host as the parent. For this scenario, the share server
   must be the same, so it does not take the limit in account, reusing the
   share server anyway.
