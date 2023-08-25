.. -*- rst -*-

Share snapshots
===============

Use the Shared File Systems service to make snapshots of shares. A share
snapshot is a point-in-time, read-only copy of the data that is
contained in a share. The APIs below allow controlling share snapshots. They
are represented by a "snapshot" resource in the Shared File Systems service,
and they can have user-defined metadata such as a name and description.

You can create, manage, update, and delete
share snapshots. After you create or manage a share snapshot, you
can create a share from it.  You can also revert a share to its most
recent snapshot.

You can update a share snapshot to rename it, change its
description, or update its state to one of these supported states:

- ``available``

- ``error``

- ``creating``

- ``deleting``

- ``error_deleting``

- ``manage_starting``

- ``manage_error``

- ``unmanage_starting``

- ``unmanage_error``

- ``restoring``

As administrator, you can also reset the state of a snapshot and
force-delete a share snapshot in any state. Use the ``policy.yaml``
file to grant permissions for these actions to other roles.


List share snapshots
~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/snapshots

Lists all share snapshots.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - all_tenants: all_tenants_query
   - name~: name_inexact_query
   - description~: description_inexact_query
   - with_count: with_count_snapshot_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_id
   - name: name

Response example
----------------

.. literalinclude:: samples/snapshots-list-response.json
   :language: javascript


List share snapshots with details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/snapshots/detail

Lists all share snapshots with details.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - all_tenants: all_tenants_query
   - name~: name_inexact_query
   - description~: description_inexact_query
   - with_count: with_count_snapshot_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_id
   - status: snapshot_status
   - share_id: snapshot_share_id
   - name: name
   - description: description
   - created_at: created_at
   - share_proto: snapshot_share_protocol
   - share_size: snapshot_share_size
   - size: snapshot_size
   - project_id: snapshot_project_id
   - user_id: snapshot_user_id
   - provider_location: snapshot_provider_location_optional

Response example
----------------

.. literalinclude:: samples/snapshots-list-detailed-response.json
   :language: javascript


Show share snapshot details
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/snapshots/{snapshot_id}

Shows details for a share snapshot.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_id
   - status: snapshot_status
   - share_id: snapshot_share_id
   - name: name
   - description: description
   - created_at: created_at
   - share_proto: snapshot_share_protocol
   - share_size: snapshot_share_size
   - size: snapshot_size
   - project_id: snapshot_project_id
   - user_id: snapshot_user_id
   - provider_location: snapshot_provider_location_optional

Response example
----------------

.. literalinclude:: samples/snapshot-show-response.json
   :language: javascript


Create share snapshot
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/snapshots

Creates a snapshot from a share.


Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 422

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: snapshot_share_id_request
   - force: force_snapshot_request
   - name: name_request
   - description: description_request
   - display_name: display_name_request
   - display_description: display_description_request

Request example
---------------

.. literalinclude:: samples/snapshot-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_id
   - share_id: snapshot_share_id
   - status: snapshot_status
   - name: name
   - description: description
   - created_at: created_at
   - share_proto: snapshot_share_protocol
   - share_size: snapshot_share_size
   - provider_location: snapshot_provider_location_optional
   - size: snapshot_size
   - project_id: snapshot_project_id
   - user_id: snapshot_user_id

Response example
----------------

.. literalinclude:: samples/snapshot-create-response.json
   :language: javascript


Manage share snapshot (since API v2.12)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/snapshots/manage

.. versionadded:: 2.12

Configures Shared File Systems to manage a share snapshot.

.. note::

   Managing snapshots of shares that are created on top of share servers
   (i.e. created with share networks) is not supported prior to API version
   2.49.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 409

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - share_id: snapshot_manage_share_id
   - provider_location: snapshot_provider_location_request
   - name: name_request
   - display_name: display_name_request
   - description: description_request
   - display_description: display_description_request
   - driver_options: driver_options

Request example
---------------

.. literalinclude:: samples/snapshot-manage-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_id
   - share_id: snapshot_share_id
   - status: snapshot_manage_status
   - name: name
   - description: description
   - created_at: created_at
   - share_proto: snapshot_share_protocol
   - share_size: snapshot_share_size
   - provider_location: snapshot_provider_location
   - size: snapshot_size
   - project_id: snapshot_project_id
   - user_id: snapshot_user_id

Response example
----------------

.. literalinclude:: samples/snapshot-manage-response.json
   :language: javascript


Unmanage share snapshot (since API v2.12)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/snapshots/{snapshot_id}/action

.. versionadded:: 2.12

Configures Shared File Systems to stop managing a share snapshot.

.. note::

   Unmanaging snapshots of shares that are created on top of share servers
   (i.e. created with share networks) is not supported prior to API version
   2.49.

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

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path
   - unmanage: snapshot_unmanage

Request example
---------------

.. literalinclude:: samples/snapshot-actions-unmanage-request.json
   :language: javascript

Response parameters
-------------------

There is no body content for the response.

Reset share snapshot state
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/snapshots/{snapshot_id}/action

Administrator only. Explicitly updates the state of a share snapshot.

Use the ``policy.yaml`` file to grant permissions for this action
to other roles.

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

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path
   - status: snapshot_status_request

Request example
---------------

.. literalinclude:: samples/snapshot-actions-reset-state-request.json
   :language: javascript


Force-delete share snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/snapshots/{snapshot_id}/action

Administrator only. Force-deletes a share snapshot in any state.

Use the ``policy.yaml`` file to grant permissions for this action
to other roles.

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

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path
   - force_delete: snapshot_force_delete

Request example
---------------

.. literalinclude:: samples/snapshot-actions-force-delete-request.json
   :language: javascript


Update share snapshot
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/snapshots/{snapshot_id}

Updates a share snapshot.

You can update these attributes:

- ``display_name``, which also changes the ``name`` of the share
  snapshot.

- ``display_description``, which also changes the ``description`` of
  the share snapshot.

If you try to update other attributes, they retain their previous
values.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403
   - 404
   - 422

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path
   - display_name: display_name_request
   - display_description: display_description_request

Request example
---------------

.. literalinclude:: samples/snapshot-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: snapshot_id
   - status: snapshot_status
   - share_id: snapshot_share_id
   - name: name
   - description: description
   - created_at: created_at
   - share_proto: snapshot_share_protocol
   - share_size: snapshot_share_size
   - size: snapshot_size
   - project_id: snapshot_project_id
   - user_id: snapshot_user_id

Response example
----------------

.. literalinclude:: samples/snapshot-update-response.json
   :language: javascript


Delete share snapshot
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/snapshots/{snapshot_id}

Deletes a share snapshot.

Preconditions

- Share snapshot status must be ``available`` or ``error``.

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

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path
