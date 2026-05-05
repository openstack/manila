.. _shared_file_systems_manage_and_unmanage_snapshot:

==================================
Manage and unmanage share snapshot
==================================

To ``manage`` a share snapshot means that an administrator, rather than a
share driver, manages the storage lifecycle. This approach is appropriate
when an administrator manages share snapshots outside of the Shared File
Systems service and wants to register it with the service.

To ``unmanage`` a share snapshot means to unregister a specified share
snapshot from the Shared File Systems service. Administrators can revert an
unmanaged share snapshot to managed status if needed.

.. _unmanage_share_snapshot:

Unmanage a share snapshot
-------------------------

The ``unmanage`` operation is not supported for shares that were
created on top of share servers and created with share networks.
The Share service should have the option
``driver_handles_share_servers = False`` set in the ``manila.conf`` file.

To unmanage managed share snapshot, run the
:command:`openstack share snapshot abandon <share_snapshot>`
command. Then try to print the
information about the share snapshot. The returned result should indicate that
Shared File Systems service won't find the share snapshot:

.. code-block:: console

   $ openstack share snapshot abandon my_test_share_snapshot
   $ openstack share snapshot show my_test_share_snapshot
   ERROR: No sharesnapshot with a name or ID of 'my_test_share_snapshot'
   exists.

.. _manage_share_snapshot:

Manage a share snapshot
-----------------------
To register the non-managed share snapshot in the File System service, run the
:command:`openstack share snapshot adopt` command:

.. code-block:: console

   openstack share snapshot adopt [--name <name>] [--description <description>]
                                  [--driver-option <key=value>]
                                  <share> <provider_location>

The positional arguments are:

- share. Name or ID of the share.

- provider_location. Provider location of the share snapshot on the backend.

The ``driver_options`` is an optional set of one or more key and value pairs
that describe driver options.

To manage share snapshot, run:

.. code-block:: console

   $ openstack share snapshot adopt \
       9ba52cc6-c97e-4b40-8653-4bcbaaf9628d \
       4d1e2863-33dd-4243-bf39-f7354752097d \
       --name my_test_share_snapshot \
       --description "My test share snapshot" \
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | id                | 89c663b5-026d-45c7-a43b-56ef0ba0faab |
   | share_id          | 9ba52cc6-c97e-4b40-8653-4bcbaaf9628d |
   | share_size        | 1                                    |
   | created_at        | 2026-03-31T04:49:42.600980           |
   | status            | manage_starting                      |
   | name              | my_test_share_snapshot               |
   | description       | My test share snapshot               |
   | size              | None                                 |
   | share_proto       | NFS                                  |
   | user_id           | d9f4003655c94db5b16c591920be1f91     |
   | project_id        | aaa33a0ca4324965a3e65ae47e864e94     |
   | provider_location | 4d1e2863-33dd-4243-bf39-f7354752097d |
   +-------------------+--------------------------------------+

Check that the share snapshot is available:

.. code-block:: console

   $ openstack share snapshot show my_test_share_snapshot
   +-------------------+--------------------------------------+
   | Field             | Value                                |
   +-------------------+--------------------------------------+
   | id                | 89c663b5-026d-45c7-a43b-56ef0ba0faab |
   | share_id          | 9ba52cc6-c97e-4b40-8653-4bcbaaf9628d |
   | share_size        | 1                                    |
   | created_at        | 2026-03-31T04:49:42.000000           |
   | status            | available                            |
   | name              | my_test_share_snapshot               |
   | description       | My test share snapshot               |
   | size              | 1                                    |
   | share_proto       | NFS                                  |
   | user_id           | d9f4003655c94db5b16c591920be1f91     |
   | project_id        | aaa33a0ca4324965a3e65ae47e864e94     |
   | provider_location | 4d1e2863-33dd-4243-bf39-f7354752097d |
   | properties        |                                      |
   +-------------------+--------------------------------------+
