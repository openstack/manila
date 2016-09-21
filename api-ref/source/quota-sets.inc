.. -*- rst -*-

==========
Quota sets
==========

Provides quotas management support.

.. important::

    For API versions 2.6 and prior, replace ``quota-sets`` in the URLs with
    ``os-quota-sets``.


Show default quota set
======================

.. rest_method::  GET /v2/{tenant_id}/quota-sets/{tenant_id}/defaults

Shows default quotas for a tenant.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - tenant_id: tenant_id

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_set: quota_set
   - id: quota_tenant_id
   - gigabytes: quota_gigabytes
   - snapshots: quota_snapshots
   - shares: quota_shares
   - snapshot_gigabytes: quota_snapshot_gigabytes
   - share_networks: quota_share_networks

Response example
----------------

.. literalinclude:: samples/quota-show-response.json
   :language: javascript


Show quota set
==============

.. rest_method::  GET /v2/{tenant_id}/quota-sets/{tenant_id}?user_id={user_id}

Shows quotas for a tenant.

If you specify the optional ``user_id`` query parameter, you get
the quotas for this user in the tenant. If you omit this parameter,
you get the quotas for the project.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - tenant_id: tenant_id
   - user_id: user_id_query

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_set: quota_set
   - id: quota_tenant_id
   - gigabytes: quota_gigabytes
   - snapshots: quota_snapshots
   - shares: quota_shares
   - snapshot_gigabytes: quota_snapshot_gigabytes
   - share_networks: quota_share_networks

Response example
----------------

.. literalinclude:: samples/quota-show-response.json
   :language: javascript


Update quota set
================

.. rest_method::  PUT /v2/{tenant_id}/quota-sets/{tenant_id}?user_id={user_id}

Updates quotas for a tenant.

If you specify the optional ``user_id`` query parameter, you update
the quotas for this user in the tenant. If you omit this parameter,
you update the quotas for the project.

Normal response codes: 200
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - tenant_id: tenant_id
   - user_id: user_id_query
   - quota_set: quota_set
   - force: force
   - gigabytes: quota_gigabytes_request
   - snapshots: quota_snapshots_request
   - snapshot_gigabytes: quota_snapshot_gigabytes_request
   - shares: quota_shares_request
   - share_networks: quota_share_networks_request

Request example
---------------

.. literalinclude:: samples/quota-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_set: quota_set
   - id: quota_tenant_id
   - gigabytes: quota_gigabytes
   - snapshots: quota_snapshots
   - shares: quota_shares
   - snapshot_gigabytes: quota_snapshot_gigabytes
   - share_networks: quota_share_networks

Response example
----------------

.. literalinclude:: samples/quota-update-response.json
   :language: javascript


Delete quota set
================

.. rest_method::  DELETE /v2/{tenant_id}/quota-sets/{tenant_id}?user_id={user_id}

Deletes quotas for a tenant. The quota reverts to the default quota.

If you specify the optional ``user_id`` query parameter, you delete
the quotas for this user in the tenant. If you omit this parameter,
you delete the quotas for the project.

Normal response codes: 202
Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id_path
   - tenant_id: tenant_id
   - user_id: user_id_query
