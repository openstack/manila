.. -*- rst -*-

Share group snapshots (since API v2.31)
=======================================

Use the Shared File Systems Service to make snapshots of share groups. A share
group snapshot is a point-in-time, read-only copy of the data that is
contained in a share group. You can create, update, and delete
share group snapshots. After you create a share group snapshot, you
can create a share group from it.

You can update a share group snapshot to rename it, change its
description, or update its state.

As administrator, you can also reset the state of a group snapshot. Use
the ``policy.yaml`` file to grant permissions for these actions to other
roles.

.. note::

    Share Group Snapshot APIs are no longer considered experimental since API
    version 2.55.

List share group snapshots
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-group-snapshots

.. versionadded:: 2.31

Lists all share group snapshots.

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
   - name: name_query
   - description: description_query
   - status: group_snapshot_status_query
   - share_group_id: share_group_id_query
   - limit: limit_query
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - name: name
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshots-list-response.json
   :language: javascript


List share group snapshots with details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-group-snapshots/detail

.. versionadded:: 2.31

Lists all share group snapshots with details.

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
   - name: name_query
   - description: description_query
   - status: group_snapshot_status_query
   - share_group_id: share_group_id_query
   - limit: limit_query
   - offset: offset
   - sort_key: sort_key
   - sort_dir: sort_dir

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - project_id: project_id
   - status: group_snapshot_status_required
   - share_group_id: share_group_id
   - name: name
   - description: description
   - created_at: created_at
   - members: group_snapshot_members
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshots-list-detailed-response.json
   :language: javascript


List share group snapshots members
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-group-snapshots/{group_snapshot_id}/members

.. versionadded:: 2.31

Lists all share group snapshots members.

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
   - group_snapshot_id: group_snapshot_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - created_at: created_at
   - project_id: project_id
   - size: snapshot_size
   - share_protocol: snapshot_share_protocol
   - name: name
   - share_group_snapshot_id: group_snapshot_id
   - share_id: snapshot_share_id


Response example
----------------

.. literalinclude:: samples/share-group-snapshots-list-members-response.json
   :language: javascript


Show share group snapshot details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-group-snapshots/{group_snapshot_id}

.. versionadded:: 2.31

Shows details for a share group snapshot.

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
   - group_snapshot_id: group_snapshot_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - project_id: project_id
   - status: group_snapshot_status_required
   - share_group_id: share_group_id
   - name: name
   - description: description
   - created_at: created_at
   - members: group_snapshot_members
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshot-show-response.json
   :language: javascript


Create share group snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-group-snapshots

.. versionadded:: 2.31

Creates a snapshot from a share.

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
   - name: name_request
   - description: description_request
   - share_group_id: share_group_id

Request example
---------------

.. literalinclude:: samples/share-group-snapshot-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - project_id: project_id
   - status: group_snapshot_status_required
   - share_group_id: share_group_id
   - name: name
   - description: description
   - created_at: created_at
   - members: group_snapshot_members
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshot-create-response.json
   :language: javascript


Reset share group snapshot state
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-group-snapshots/{group_snapshot_id}/action

.. versionadded:: 2.31

Administrator only. Explicitly updates the state of a share group snapshot.

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
   - group_snapshot_id: group_snapshot_id_path
   - status: group_snapshot_status_required

Request example
---------------

.. literalinclude:: samples/snapshot-actions-reset-state-request.json
   :language: javascript


Update share group snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/share-group-snapshots/{group_snapshot_id}

.. versionadded:: 2.31

Updates a share group snapshot.

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
   - group_snapshot_id: group_snapshot_id_path
   - name: name_request
   - description: description_request

Request example
---------------

.. literalinclude:: samples/snapshot-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: group_snapshot_id
   - project_id: project_id
   - status: group_snapshot_status_required
   - share_group_id: share_group_id
   - name: name
   - description: description
   - created_at: created_at
   - members: group_snapshot_members
   - links: group_snapshot_links

Response example
----------------

.. literalinclude:: samples/share-group-snapshot-update-response.json
   :language: javascript


Delete share group snapshot
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-group-snapshots/{group_snapshot_id}

.. versionadded:: 2.31

Deletes a share group snapshot.

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
   - group_snapshot_id: group_snapshot_id_path
