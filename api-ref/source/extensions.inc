.. -*- rst -*-

==============
API extensions
==============

Lists available Shared File Systems API extensions.


List extensions
===============

.. rest_method::  GET /v2/{tenant_id}/extensions

Lists all extensions.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: extension_name
   - links: extension_links
   - description: extension_description
   - alias: extension_alias
   - updated: extension_updated

Response example
----------------

.. literalinclude:: samples/extensions-list-response.json
   :language: javascript
