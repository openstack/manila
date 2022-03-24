.. -*- rst -*-

API extensions
==============

Lists available Shared File Systems API extensions.


List extensions
~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/extensions

Lists all extensions.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: extension_name
   - links: extension_links
   - description: extension_description
   - alias: extension_alias
   - updated: updated_at_extensions

Response example
----------------

.. literalinclude:: samples/extensions-list-response.json
   :language: javascript
