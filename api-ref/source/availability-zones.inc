.. -*- rst -*-

==================
Availability zones
==================

Describes availability zones that the Shared File Systems service is
configured with.

.. important::

    For API versions 2.6 and prior, replace ``availability-zones`` in the URLs
    with ``os-availability-zone``.


List availability zones
=======================

.. rest_method::  GET /v2/{tenant_id}/availability-zones

Lists all availability zones.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - availability_zones: availability_zones
   - id: id_9
   - name: name_6
   - created_at: created_at_7
   - updated_at: updated_at_4

Response example
----------------

.. literalinclude:: samples/availability-zones-list-response.json
   :language: javascript
