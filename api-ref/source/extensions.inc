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

   - tenant_id: tenant_id_1

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - name: name_10
   - links: links_2
   - description: description_8
   - alias: alias
   - updated: updated

Response example
----------------

.. literalinclude:: samples/extensions-list-response.json
   :language: javascript
