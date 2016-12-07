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
   - id: availability_zone_id
   - name: availability_zone_name
   - created_at: availability_zone_created_at
   - updated_at: availability_zone_updated_at

Response example
----------------

.. literalinclude:: samples/availability-zones-list-response.json
   :language: javascript
