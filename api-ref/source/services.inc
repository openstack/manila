.. -*- rst -*-

========
Services
========

These APIs help in interacting with the Shared File Systems services,
``manila-scheduler``, ``manila-share`` and ``manila-data``.

.. important::

    For API versions 2.6 and prior, replace ``services``` in the URLs
    with ``os-services``.


List services
=============

.. rest_method::  GET /v2/{tenant_id}/services?host={host}&binary={binary}&zone={zone}&state={state}&status={status}

Lists all services optionally filtered with the specified search options.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - host: host_12
   - binary: binary_3
   - zone: zone_1
   - state: state_2
   - status: status_17

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - services: services
   - id: id_12
   - status: status_4
   - binary: binary_2
   - zone: zone
   - host: host_5
   - state: state_1
   - updated_at: updated_at_5

Response example
----------------

.. literalinclude:: samples/services-list-response.json
   :language: javascript


Enable service
==============

.. rest_method::  PUT /v2/{tenant_id}/services/enable

Enables a service.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - binary: binary_1
   - host: host_3

Request example
---------------

.. literalinclude:: samples/service-enable-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - host: host_14
   - binary: binary_5
   - disabled: disabled

Response example
----------------

.. literalinclude:: samples/service-enable-response.json
   :language: javascript


Disable service
===============

.. rest_method::  PUT /v2/{tenant_id}/services/disable

Disables a service.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403),
itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_1
   - binary: binary
   - host: host_2

Request example
---------------

.. literalinclude:: samples/service-disable-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - host: host_13
   - binary: binary_4
   - disabled: disabled

Response example
----------------

.. literalinclude:: samples/service-disable-response.json
   :language: javascript
