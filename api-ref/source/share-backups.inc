.. -*- rst -*-

Share backups (since API v2.80)
===============================

Use the Shared File Systems service to make backups of shares. A share
backup is a point-in-time, read-only copy of the data that is
contained in a share. The APIs below allow controlling share backups. They
are represented by a "backup" resource in the Shared File Systems service,
and they can have user-defined metadata such as a name and description.

You can create, restore, update, list and delete share backups. After you
create a share backup, you can access backup and use it. You can also restore
a backup into a share as long as certain criteria are met e.g. size.

You can update a share backup to change its name or description. As
administrator, you can also reset the state of a backup. Backup can be in
one of the following states:

- ``available``

- ``error``

- ``creating``

- ``deleting``

- ``restoring``


During a backup or restore operation, share can be in one of the following
states:

- ``available``

- ``backup_creating``

- ``backup_restoring``

- ``backup_restoring_error``


List share backups
~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-backups

.. versionadded:: 2.80

Lists all share backups.

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

   - share_id: backup_share_id_query
   - name~: name_inexact_query_versionless
   - description~: description_inexact_query_versionless
   - limit: limit
   - offset: offset
   - sort_key: sort_key_backup
   - sort_dir: sort_dir
   - status: backup_status_query
   - host: backup_host_query
   - topic: backup_topic_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: backup_id_response
   - share_id: backup_share_id
   - status: backup_status

Response example
----------------

.. literalinclude:: samples/share-backups-list-response.json
   :language: javascript


List share backups with details
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-backups/detail

.. versionadded:: 2.80

Lists all share backups with details.

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

   - share_id: backup_share_id_query
   - name~: name_inexact_query_versionless
   - description~: description_inexact_query_versionless
   - limit: limit
   - offset: offset
   - sort_key: sort_key_backup
   - sort_dir: sort_dir
   - status: backup_status_query
   - host: backup_host_query
   - topic: backup_topic_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: backup_id_response
   - share_id: backup_share_id
   - status: backup_status
   - size: backup_size
   - availability_zone: backup_az
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - progress: backup_progress
   - restore_progress: backup_restore_progress

Response example
----------------

.. literalinclude:: samples/share-backups-list-detailed-response.json
   :language: javascript


Show share backup details
~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-backups/{backup_id}

.. versionadded:: 2.80

Shows details for a share backup.

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

   - backup_id: backup_id_request_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: backup_id_response
   - share_id: backup_share_id
   - status: backup_status
   - size: backup_size
   - availability_zone: backup_az
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - progress: backup_progress
   - restore_progress: backup_restore_progress

Response example
----------------

.. literalinclude:: samples/share-backup-show-response.json
   :language: javascript


Create share backup
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-backups

.. versionadded:: 2.80

Creates a backup from a share.


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
   - 422

Request
-------

.. rest_parameters:: parameters.yaml

   - share_id: backup_share_id
   - name: name_request
   - description: description_request
   - backup_options: backup_options_request

Request example
---------------

.. literalinclude:: samples/share-backup-create-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: backup_id_response
   - share_id: backup_share_id
   - status: backup_status
   - size: backup_size
   - availability_zone: backup_az
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - progress: backup_progress
   - restore_progress: backup_restore_progress

Response example
----------------

.. literalinclude:: samples/share-backup-create-response.json
   :language: javascript


Update share backup
~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/share-backups/{backup_id}

.. versionadded:: 2.80

Updates a share backup.

You can update these attributes:

- ``display_name``, which changes the ``name`` of the share backup.

- ``display_description``, which changes the ``description`` of
  the share backup.

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

Request
-------

.. rest_parameters:: parameters.yaml

   - backup_id: backup_id_request_path
   - display_name: display_name_request
   - display_description: display_description_request

Request example
---------------

.. literalinclude:: samples/share-backup-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - id: backup_id_response
   - share_id: backup_share_id
   - status: backup_status
   - size: backup_size
   - availability_zone: backup_az
   - name: name
   - description: description
   - created_at: created_at
   - updated_at: updated_at
   - progress: backup_progress
   - restore_progress: backup_restore_progress

Response example
----------------

.. literalinclude:: samples/share-backup-update-response.json
   :language: javascript


Delete share backup
~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-backups/{backup_id}

.. versionadded:: 2.80

Deletes a share backup.

Preconditions

- Share backup status must be ``available`` or ``error``.

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

   - backup_id: backup_id_request_path


Restore a share backup
~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-backups/{backup_id}/action

.. versionadded:: 2.80

Restores a share backup into original share.

Preconditions

- Share backup status must be ``available``.

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

   - backup_id: backup_id_request_path

Request example
---------------

.. literalinclude:: samples/share-backup-restore-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - backup_id: backup_id_response
   - share_id: backup_share_id

Response example
----------------

.. literalinclude:: samples/share-backup-restore-response.json
   :language: javascript


Reset share backup status
~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-backups/{backup_id}/action

.. versionadded:: 2.80

Administrator only. Explicitly updates the state of a share backup.

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
   - backup_id: backup_id_request_path
   - status: backup_status_request

Request example
---------------

.. literalinclude:: samples/share-backup-reset-status-request.json
   :language: javascript
