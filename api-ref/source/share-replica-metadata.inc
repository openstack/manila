.. -*- rst -*-

Share Replica Metadata (Since API v2.95)
========================================

Shows, sets, updates, and unsets share replica metadata.


Show all share replica metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-replicas/{share_replica_id}/metadata

.. versionadded:: 2.95

Shows all the metadata for a share replica, as key and value pairs.

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
   - share_replica_id: share_replica_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-replica-show-metadata-response.json
   :language: javascript


Show share replica metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/share-replicas/{share_replica_id}/metadata/{key}

.. versionadded:: 2.95

Retrieves a specific metadata item from a share replica's metadata by its key. If
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
   - share_replica_id: share_replica_id_path
   - key: metadata_key_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata_item

Response example
----------------

.. literalinclude:: samples/share-replica-show-metadata-item-response.json
   :language: javascript


Set share replica metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/share-replicas/{share_replica_id}/metadata

.. versionadded:: 2.95

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
   - share_replica_id: share_replica_id_path
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/share-replica-set-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-replica-set-metadata-response.json
   :language: javascript


Update share replica metadata
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/share-replicas/{share_replica_id}/metadata

.. versionadded:: 2.95

Replaces the metadata for a given share replica with the metadata (specified as
key-value pairs) in the request object. All pre-existing metadata of the
share replica will be deleted and replaced with the new metadata supplied.

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
   - share_replica_id: share_replica_id_path
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/share-replica-update-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-replica-update-metadata-response.json
   :language: javascript


To delete all existing metadata items on a given share replica,
the request object needs to specify an empty metadata object:

Request example
---------------

.. literalinclude:: samples/share-replica-update-null-metadata-request.json
   :language: javascript

Response example
----------------

.. literalinclude:: samples/share-replica-update-null-metadata-response.json
   :language: javascript


Delete share replica metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/share-replicas/{share_replica_id}/metadata/{key}

.. versionadded:: 2.95

Deletes a single metadata item on a share replica, identified by its key. If
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
   - share_replica_id: share_replica_id_path
   - key: metadata_key_path
```