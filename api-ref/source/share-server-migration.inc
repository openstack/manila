.. -*- rst -*-

Share Server Migration (since API v2.57)
========================================

The Share Server Migration API is an administrator-only experimental API that
allows the invoker to select a destination backend to migrate a share server
to.

Share server migration uses a 2-phased approach. In the first phase of the
migration, the data copying or replication operations are performed, so it's
the longer phase. After the first phase is finished, the administrator can
trigger the second phase, which consists in final syncs and making the new
share server available to be used and the latter one inactive.

During the data copy phase, source shares will remain available and writable
if it was required by the administrator and supported by the share driver.
After the second phase, users may need to reconnect to the shares affected by
the migration.
All shares belonging to a share server are migrated and their access rules are
preserved through the migration.
The share snapshots are going to be copied if specified by the administrator
and/or supported by the driver.

.. important::
  In order to migrate a share server, the administrator must make sure that
  none of the shares on the server are replicated or in a share group.

.. note::

    Share Server Migration APIs are `experimental APIs <#experimental-apis>`_ .

Possible uses for share server migration include:

 - Migrating a share server and all its shares and snapshots at once.
 - Bring down a physical storage device for maintenance.
 - Free up space in a thinly-provisioned back end.
 - Load balancing among backends.


Share Server Migration Check Compatibility
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/{project_id}/share_servers/{share_server_id}/action

.. versionadded:: 2.57

Checks if a share driver can handle a share server migration according to
the specified destination host and ``new_share_network_id``, as well as the
``writable``, ``nondisruptive`` and ``preserve_snapshots`` flags.

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
   - share_server_id: share_server_id
   - preserve_snapshots: preserve_snapshots_server_migration
   - nondisruptive: nondisruptive_server_migration
   - writable: writable_server_migration
   - new_share_network_id: new_share_network_id_server_migration
   - host: host_share_server_migration

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - compatible: compatible
   - requested_capabilities: requested_capabilities
   - supported_capabilities: supported_capabilities

Request example
---------------

.. literalinclude:: samples/share-server-migration-check-compatibility-request.json
   :language: javascript

Response example
----------------

.. literalinclude:: samples/share-server-migration-check-compatibility-response.json
   :language: javascript


Start a Share Server Migration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/{project_id}/share_servers/{share_server_id}/action

.. versionadded:: 2.57

Triggers a share server migration. This API will initiate the first phase of
the share server migration to a new host.

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
   - share_server_id: share_server_id
   - preserve_snapshots: preserve_snapshots_server_migration
   - nondisruptive: nondisruptive_server_migration
   - writable: writable_server_migration
   - new_share_network_id: new_share_network_id_server_migration
   - host: host_share_server_migration

Request example
---------------

.. literalinclude:: samples/share-server-migration-start-request.json
   :language: javascript


Complete Share Server Migration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/{project_id}/share_servers/{share_server_id}/action

.. versionadded:: 2.57

Completes share server migration. This API will initiate the switch-over
from the source to destination share server. This operation can be disruptive.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id
   - share_server_id: share_server_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - total_progress: total_progress_server_migration
   - task_state: task_state_server_migration
   - destination_share_server_id: destination_share_server_id

Request example
---------------

.. literalinclude:: samples/share-server-migration-complete-request.json
   :language: javascript

Response example
----------------

.. literalinclude:: samples/share-server-migration-complete-response.json
   :language: javascript


Share Server Migration Get Progress
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/{project_id}/share_servers/{share_server_id}/action

.. versionadded:: 2.57

Returns the completed percentage and the destination share server id of an
ongoing share server migration.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - share_server_id: share_server_id
   - project_id: project_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - total_progress: total_progress_server_migration
   - task_state: task_state_server_migration
   - destination_share_server_id: destination_share_server_id

Request example
---------------

.. literalinclude:: samples/share-server-migration-get-progress-request.json
   :language: javascript

Response example
----------------

.. literalinclude:: samples/share-server-migration-get-progress-response.json
   :language: javascript


Cancel Share Server Migration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method:: POST /v2/{project_id}/share_servers/{share_server_id}/action

.. versionadded:: 2.57

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - share_server_id: share_server_id
   - project_id: project_id

Request example
---------------

.. literalinclude:: samples/share-server-migration-cancel-request.json
   :language: javascript
