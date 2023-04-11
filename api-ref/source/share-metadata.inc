.. -*- rst -*-

Share metadata
==============

Shows, sets, updates, and unsets share metadata.


Show all share metadata
~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/shares/{share_id}/metadata

Shows all the metadata for a share, as key and value pairs.

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
   - share_id: share_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-show-metadata-response.json
   :language: javascript


Show share metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/shares/{share_id}/metadata/{key}

Retrieves a specific metadata item from a share's metadata by its key. If
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
   - share_id: share_id
   - key: metadata_key_request

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata_item

Response example
----------------

.. literalinclude:: samples/share-show-metadata-item-response.json
   :language: javascript


Set share metadata
~~~~~~~~~~~~~~~~~~

.. rest_method::  POST /v2/shares/{share_id}/metadata

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
   - share_id: share_id
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/share-set-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-set-metadata-response.json
   :language: javascript


Update share metadata
~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/shares/{share_id}/metadata

Replaces the metadata for a given share with the metadata (specified as
key-value pairs) in the request object. All pre-existing metadata of the
share will be deleted and replaced with the new metadata supplied.

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
   - share_id: share_id
   - metadata: metadata_request


Request example
---------------

.. literalinclude:: samples/share-update-metadata-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - metadata: metadata

Response example
----------------

.. literalinclude:: samples/share-update-metadata-response.json
   :language: javascript


To delete all existing metadata items on a given share, the request object
needs to specify an empty metadata object:

Request example
---------------

.. literalinclude:: samples/share-update-null-metadata-request.json
   :language: javascript

Response example
----------------

.. literalinclude:: samples/share-update-null-metadata-response.json
   :language: javascript


Delete share metadata item
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/shares/{share_id}/metadata/{key}

Deletes a single metadata item on a share, idetified by its key. If
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
   - share_id: share_id
   - key: metadata_key_request
