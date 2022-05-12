.. -*- rst -*-

Share Migration (since API v2.22)
=================================

The Share Migration API is an administrator-only experimental API that allows
the invoker to select a destination pool to migrate a share to,
while still allowing clients to access the source
"share instance" during migration.

Share migration is implemented in a 2-phase approach. The first phase of
migration is when operations that take the longest are performed, such as
data copying or replication. After first phase of data copying is complete,
it is up to administrator to trigger the second phase,
often referred to as switchover phase, which may perform operations
such as final sync and deleting the source share instance.

During the data copy phase, user can remain connected to the source, and may have
to reconnect after the switchover phase. In order to migrate a share, manila
may employ one of two mechanisms which are driver-assisted migration and
host-assisted migration.

- ``Driver-assisted migration``: This mechanism is intended to make use of driver
    optimizations to migrate shares between pools of the same storage vendor.
    This mechanism allows migrating shares nondisruptively while the source
    remains writable, preserving all filesystem metadata and snapshots.
    The migration workload is performed in the storage back end.

- ``Host-assisted migration``: This mechanism is intended to migrate
    shares in an agnostic manner between two different pools, regardless
    of storage vendor. The implementation for this mechanism does not
    offer the same properties found in driver-assisted migration.
    In host-assisted migration, the source remains readable,
    snapshots must be deleted prior to starting the migration,
    filesystem metadata may be lost, and the clients will get
    disconnected by the end of migration. The migration workload
    is performed by the Data Service, which is a dedicated
    manila service for intensive data operations.

These methods provide different capabilities
and affect how efficiently the data copy and switchover
are achieved. Generally speaking, driver-assisted migration is
limited to homogenous storage backends and when available,
is expected to be faster and more efficient than host-assisted migration.
Driver-assisted migration occurs on the storage backend,
while host-assisted migration occurs on the OpenStack nodes
running the manila data service.

When starting a migration, ``driver-assisted migration`` is
attempted first. If the shared file system service detects
it is not possible to perform the ``driver-assisted
migration``, it proceeds to attempt
``host-assisted migration``.

Possible use cases for data migration include:

 - Migrating shares along with snapshots.
 - Bring down a physical storage device for maintenance
 - Free up space in a thinly-provisioned back end.
 - Load balancing among share servers.
 - Retyping a share

.. note::

    Share Migration APIs are `experimental APIs <#experimental-apis>`_ .


Start Migration
~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/shares/{share_id}/action

.. versionadded:: 2.22

Initiates share migration. This API will initiate the share data copy to the
new host. The copy operation is non-disruptive.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id
   - share_id: share_id
   - force_host_assisted_migration: force_host_assisted_migration
   - preserve_snapshots: preserve_snapshots
   - preserve_metadata: preserve_metadata
   - nondisruptive: nondisruptive
   - writable: writable
   - new_share_type_id: new_share_type_id
   - new_share_network_id: new_share_network_id
   - host: host

Request example
---------------

.. literalinclude:: samples/share-migration-start-request.json
   :language: javascript


Complete Migration
~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

.. versionadded:: 2.22

Completes share migration. This API will initiate the switch-over from the
source to destination share. This operation can be disruptive.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id
   - share_id: share_id

Request example
---------------

.. literalinclude:: samples/share-migration-complete-request.json
   :language: javascript


Migration Get Process
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

.. versionadded:: 2.22

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - project_id: project_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - details: migration_progress_details
   - total_progress: total_progress
   - task_state: task_state

Request example
---------------

.. literalinclude:: samples/share-migration-get-process-request.json
   :language: javascript

Response_parameters
-------------------

.. literalinclude:: samples/share-migration-get-process-response.json
   :language: javascript


Cancel Migration
~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/action

.. versionadded:: 2.22

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: share_id
   - project_id: project_id

Request example
---------------

.. literalinclude:: samples/share-migration-cancel-request.json
   :language: javascript
