.. -*- rst -*-

Snapshot metadata (Since API v2.73)
===================================

Shows, sets, updates, and unsets snapshot metadata.


Show all snapshot metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/snapshots/{snapshot_id}/metadata

.. versionadded:: 2.73

Shows all the metadata for a snapshot, as key and value pairs.

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

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/snapshot-show-metadata-response.json
   :language: javascript


Show snapshot metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/snapshots/{snapshot_id}/metadata/{key}

.. versionadded:: 2.73

Retrieves a specific metadata item from a snapshot's metadata by its key. If
the specified key does not represent a valid metadata item, the API will
respond with HTTP 404.

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

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path
   - key: metadata_key_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata_item

Response example
----------------

.. literalinclude:: samples/snapshot-show-metadata-item-response.json
   :language: javascript


Set snapshot metadata
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/snapshots/{snapshot_id}/metadata

.. versionadded:: 2.73

Allows adding new metadata items as key-value pairs. This API will not delete
pre-existing metadata items. If the request object contains metadata items
that already exist, they will be updated with new values as specified in the
request object.

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
   - snapshot_id: snapshot_id_path
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/snapshot-set-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/snapshot-set-metadata-response.json
   :language: javascript


Update snapshot metadata
~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/snapshots/{snapshot_id}/metadata

.. versionadded:: 2.73

Replaces the metadata for a given snapshot with the metadata (specified as
key-value pairs) in the request object. All pre-existing metadata of the
snapshot will be deleted and replaced with the new metadata supplied.

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

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/snapshot-update-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/snapshot-update-metadata-response.json
   :language: javascript


To delete all existing metadata items on a given snapshot, the request object
needs to specify an empty metadata object:

Request example
---------------

.. literalinclude:: samples/snapshot-update-null-metadata-request.json
   :language: javascript

Response example
----------------

.. literalinclude:: samples/snapshot-update-null-metadata-response.json
   :language: javascript


Delete snapshot metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/snapshots/{snapshot_id}/metadata/{key}

.. versionadded:: 2.73

Deletes a single metadata item on a snapshot, idetified by its key. If
the specified key does not represent a valid metadata item, the API will
respond with HTTP 404.

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

   - project_id: project_id_path
   - snapshot_id: snapshot_id_path
   - key: metadata_key_path
