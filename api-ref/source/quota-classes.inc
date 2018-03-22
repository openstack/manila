.. -*- rst -*-

===============
Quota class set
===============

Quota classes can be shown and updated for a project.

Show quota classes for a project
================================

.. rest_method::  GET /v2/{tenant_id}/quota-class-sets/{quota_class_name}

Shows quota class set for a project. If no specific value for the quota class
resource exists, then the default value will be reported.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id
   - quota_class_name: quota_class_name


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_class_set: quota_class_set
   - share_groups: maxTotalShareGroups
   - gigabytes: maxTotalShareGigabytes
   - share_group_snapshots: maxTotalShareGroupSnapshots
   - snapshots: maxTotalShareSnapshots
   - snapshot_gigabytes: maxTotalSnapshotGigabytes
   - shares: maxTotalShares
   - id: quota_class_id
   - share_networks: maxTotalShareNetworks

Response Example
----------------

.. literalinclude:: ./samples/quota-classes-show-response.json
   :language: javascript


Update quota classes for a project
==================================

.. rest_method::  PUT /v2/{tenant_id}/quota-class-sets/{quota_class_name}

Updates quota class set for a project. If the ``quota_class_name`` key does not
exist, then the API will create one.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 200

.. rest_status_code:: error status.yaml

   - 400
   - 403
   - 404

Request
-------

.. rest_parameters:: parameters.yaml

   - tenant_id: tenant_id
   - quota_class_name: quota_class_name
   - shares: maxTotalSharesOptional
   - snapshots: maxTotalShareSnapshotsOptional
   - gigabytes: maxTotalShareGigabytesOptional
   - snapshot-gigabytes: maxTotalSnapshotGigabytesOptional
   - share-networks: maxTotalShareNetworksOptional

Request Example
---------------

.. literalinclude:: ./samples/quota-classes-update-request.json
   :language: javascript


Response Parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_class_set: quota_class_set
   - share_groups: maxTotalShareGroups
   - gigabytes: maxTotalShareGigabytes
   - share_group_snapshots: maxTotalShareGroupSnapshots
   - snapshots: maxTotalShareSnapshots
   - snapshot_gigabytes: maxTotalSnapshotGigabytes
   - shares: maxTotalShares
   - share_networks: maxTotalShareNetworks

Response Example
----------------

.. literalinclude:: ./samples/quota-classes-update-response.json
   :language: javascript
