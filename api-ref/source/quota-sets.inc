.. -*- rst -*-

Quota sets
==========

Provides quotas management support.

.. important::

    For API versions 2.6 and prior, replace ``quota-sets`` in the URLs with
    ``os-quota-sets``.

    Share type quotas were added in API version 2.39. It is possible to set
    quotas per share type for the following quota resources:

    - ``gigabytes``
    - ``snapshots``
    - ``shares``
    - ``snapshot_gigabytes``
    - ``share_groups`` (since API version 2.40)
    - ``share_group_snapshots`` (since API version 2.40)
    - ``share_replicas`` (since API version 2.53)
    - ``replica_gigabytes`` (since API version 2.53)
    - ``per_share_gigabytes`` (since API version 2.62)
    - ``backups`` (since API version 2.80)
    - ``backup_gigabytes`` (since API version 2.80)

    In order to manipulate share type quotas, the requests will be similar
    to the examples below, except that the ``user_id={user_id}`` must be
    replaced by ``share_type={share_type_name_or_id}`` in the request path.

    Share groups and share group snapshots were added to quota management
    APIs in API version 2.40.

    Share replicas and replica gigabytes were added to quota management
    APIs in API version 2.53.

    Per share gigabytes was added to quota management APIs in API
    version 2.62.

    Share backups and backup gigabytes were added to quota management
    APIs in API version 2.80.


Show default quota set
~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/quota-sets/{project_id_quota_request_path}/defaults

Shows default quotas for a given project.

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
   - project_id_quota_request_path: project_id_quota_request_path

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_set: quota_set
   - id: quota_project_id
   - gigabytes: quota_gigabytes
   - snapshots: quota_snapshots
   - shares: quota_shares
   - snapshot_gigabytes: quota_snapshot_gigabytes
   - share_networks: quota_share_networks
   - share_groups: quota_share_groups
   - share_group_snapshots: quota_share_group_snapshots
   - share_networks: quota_share_networks_default
   - share_replicas: quota_share_replicas
   - replica_gigabytes: quota_replica_gigabytes
   - per_share_gigabytes: quota_per_share_gigabytes
   - backups: quota_backups
   - backup_gigabytes: quota_backup_gigabytes

Response example
----------------

.. literalinclude:: samples/quota-show-response.json
   :language: javascript


Show quota set
~~~~~~~~~~~~~~

.. rest_method::  GET /v2/quota-sets/{project_id_quota_request_path}?user_id={user_id}

Shows quotas for a given project..

If you specify the optional ``user_id`` query parameter, you get
the quotas for this user in the project. If you omit this parameter,
you get the quotas for the project.

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
   - project_id_quota_request_path: project_id_quota_request_path
   - user_id: user_id_query
   - share_type: share_type_for_quota

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_set: quota_set
   - id: quota_project_id
   - gigabytes: quota_gigabytes
   - snapshots: quota_snapshots
   - shares: quota_shares
   - snapshot_gigabytes: quota_snapshot_gigabytes
   - share_networks: quota_share_networks
   - share_groups: quota_share_groups
   - share_group_snapshots: quota_share_group_snapshots
   - share_replicas: quota_share_replicas
   - replica_gigabytes: quota_replica_gigabytes
   - per_share_gigabytes: quota_per_share_gigabytes
   - backups: quota_backups
   - backup_gigabytes: quota_backup_gigabytes

Response example
----------------

.. literalinclude:: samples/quota-show-response.json
   :language: javascript


Show quota set in detail (since API v2.25)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. rest_method::  GET /v2/quota-sets/{project_id_quota_request_path}/detail?user_id={user_id}

.. versionadded:: 2.25

Shows quotas for a project in detail.

If you specify the optional ``user_id`` query parameter, you get
the quotas for this user in the project. If you omit this parameter,
you get the quotas for the project.

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
   - project_id_quota_request_path: project_id_quota_request_path
   - user_id: user_id_query
   - share_type: share_type_for_quota

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_set: quota_set
   - id: quota_project_id
   - gigabytes: quota_gigabytes_detail
   - snapshots: quota_snapshots_detail
   - shares: quota_shares_detail
   - snapshot_gigabytes: quota_snapshot_gigabytes_detail
   - share_networks: quota_share_networks_detail
   - share_groups: quota_share_groups_detail
   - share_group_snapshots: quota_share_group_snapshots_detail
   - share_replicas: quota_share_replicas_detail
   - replica_gigabytes: quota_replica_gigabytes_detail
   - per_share_gigabytes: quota_per_share_gigabytes_detail
   - backups: quota_backups_detail
   - backup_gigabytes: quota_backup_gigabytes_detail

Response example
----------------

.. literalinclude:: samples/quota-show-detail-response.json
   :language: javascript


Update quota set
~~~~~~~~~~~~~~~~

.. rest_method::  PUT /v2/quota-sets/{project_id_quota_request_path}?user_id={user_id}

Updates quotas for a project.

If you specify the optional ``user_id`` query parameter, you update
the quotas for this user in the project. If you omit this parameter,
you update the quotas for the project.

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
   - project_id_quota_request_path: project_id_quota_request_path
   - user_id: user_id_query
   - quota_set: quota_set
   - force: force
   - gigabytes: quota_gigabytes_request
   - snapshots: quota_snapshots_request
   - snapshot_gigabytes: quota_snapshot_gigabytes_request
   - shares: quota_shares_request
   - share_networks: quota_share_networks_request
   - share_groups: quota_share_groups_request
   - share_group_snapshots: quota_share_group_snapshots_request
   - share_type: share_type_for_quota
   - share_replicas: quota_share_replicas_request
   - replica_gigabytes: quota_replica_gigabytes_request
   - per_share_gigabytes: quota_per_share_gigabytes_request
   - backups: quota_backups_request
   - backup_gigabytes: quota_backup_gigabytes_request

Request example
---------------

.. literalinclude:: samples/quota-update-request.json
   :language: javascript

Response parameters
-------------------

.. rest_parameters:: parameters.yaml

   - quota_set: quota_set
   - id: quota_project_id
   - gigabytes: quota_gigabytes
   - snapshots: quota_snapshots
   - shares: quota_shares
   - snapshot_gigabytes: quota_snapshot_gigabytes
   - share_networks: quota_share_networks
   - share_groups: quota_share_groups
   - share_group_snapshots: quota_share_group_snapshots
   - share_replicas: quota_share_replicas
   - replica_gigabytes: quota_replica_gigabytes
   - per_share_gigabytes: quota_per_share_gigabytes
   - backups: quota_backups
   - backup_gigabytes: quota_backup_gigabytes

Response example
----------------

.. literalinclude:: samples/quota-update-response.json
   :language: javascript


Delete quota set
~~~~~~~~~~~~~~~~

.. rest_method::  DELETE /v2/quota-sets/{project_id_quota_request_path}?user_id={user_id}

Deletes quotas for a project. The quota reverts to the default quota.

If you specify the optional ``user_id`` query parameter, you delete
the quotas for this user in the project. If you omit this parameter,
you delete the quotas for the project.

Response codes
--------------

.. rest_status_code:: success status.yaml

   - 202

.. rest_status_code:: error status.yaml

   - 400
   - 401
   - 403

Request
-------

.. rest_parameters:: parameters.yaml

   - project_id: project_id_path
   - project_id_quota_request_path: project_id_quota_request_path
   - user_id: user_id_query
   - share_type: share_type_for_quota
