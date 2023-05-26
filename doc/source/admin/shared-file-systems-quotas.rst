.. _shared_file_systems_quotas:

=================
Quotas and limits
=================

Limits are usage restrictions imposed on consumers of the Shared File
Systems service (manila). These limits can be of two types:

* Limits on resource consumption (also referred to as ``quotas``)
* Limits on usage of APIs (also referred to as ``rate-limits``)

Administrators can setup and manipulate these limits at any point of time.
Users can query their rate limits and quotas. If an administrator does
not set up limits explicitly, the service does not impose any rate limits
but it enforces default resource limits (also referred to as ``default
quotas``).

Users can query their absolute limits using the :command:`manila
absolute-limits` command.

.. code-block:: console

   $ manila absolute-limits
   +----------------------------+-------+
   | Name                       | Value |
   +----------------------------+-------+
   | maxTotalShareGigabytes     | 1000  |
   | maxTotalShareNetworks      | 10    |
   | maxTotalShareSnapshots     | 50    |
   | maxTotalShares             | 50    |
   | maxTotalSnapshotGigabytes  | 1000  |
   | maxTotalShareReplicas      | 100   |
   | maxTotalReplicaGigabytes   | 1000  |
   | totalShareGigabytesUsed    | 1     |
   | totalShareNetworksUsed     | 2     |
   | totalShareSnapshotsUsed    | 1     |
   | totalSharesUsed            | 1     |
   | totalSnapshotGigabytesUsed | 1     |
   | totalShareReplicasUsed     | 1     |
   | totalReplicaGigabytesUsed  | 1     |
   +----------------------------+-------+

API Rate Limits
~~~~~~~~~~~~~~~

API Rate limits control the frequency at which users can make specific API
requests. Administrators can use rate limiting on the type and
number of API calls that can be made in a specific time interval. For example,
a rate limit can control the number of ``GET`` requests processed
during a one-minute period.

To set API rate limits, copy and modify the ``etc/manila/api-paste.ini`` file.
You need to restart ``manila-api`` service after you edit the ``api-paste.ini``
file.

.. code-block:: ini

   [filter:ratelimit]
   paste.filter_factory = manila.api.v1.limits:RateLimitingMiddleware.factory
   limits = (POST, "*/shares", ^/shares, 120, MINUTE);(PUT, "*/shares", .*, 120, MINUTE);(DELETE, "*", .*, 120, MINUTE)

Also, add the ``ratelimit`` to ``noauth`` and ``keystone`` parameters in
the ``[composite:openstack_share_api]`` and
``[composite:openstack_share_api_v2]`` groups.

.. code-block:: ini

   [composite:openstack_share_api]
   use = call:manila.api.middleware.auth:pipeline_factory
   noauth = cors faultwrap ssl ratelimit sizelimit noauth api
   keystone = cors faultwrap ssl ratelimit sizelimit authtoken keystonecontext api
   keystone_nolimit = cors faultwrap ssl sizelimit authtoken keystonecontext api

   [composite:openstack_share_api_v2]
   use = call:manila.api.middleware.auth:pipeline_factory
   noauth = cors faultwrap ssl ratelimit sizelimit noauth apiv2
   keystone = cors faultwrap ssl ratelimit sizelimit authtoken keystonecontext apiv2
   keystone_nolimit = cors faultwrap ssl sizelimit authtoken keystonecontext apiv2

Finally, set the ``[DEFAULT]/api_rate_limit`` parameter in ``manila.conf`` to
``True``.

.. code-block:: ini

   [DEFAULT]
   api_rate_limit=True

To see the rate limits, run:

.. code-block:: console

   $ manila rate-limits
   +--------+------------+-------+--------+--------+----------------------+
   | Verb   | URI        | Value | Remain | Unit   | Next_Available       |
   +--------+------------+-------+--------+--------+----------------------+
   | DELETE | "*"        | 120   | 120    | MINUTE | 2015-10-20T15:17:20Z |
   | POST   | "*/shares" | 120   | 120    | MINUTE | 2015-10-20T15:17:20Z |
   | PUT    | "*/shares" | 120   | 120    | MINUTE | 2015-10-20T15:17:20Z |
   +--------+------------+-------+--------+--------+----------------------+

Default Resource Quotas
~~~~~~~~~~~~~~~~~~~~~~~

It is possible to set limits on the number of ``shares``, ``snapshots``,
``share-networks``, ``share_groups`` (requires API version 2.40),
``share_group_snapshots`` (requires API version 2.40) and
``share_replicas`` (requires API version 2.53). Alongside limits can also be
set on capacity with ``gigabytes`` (total size of shares allowed),
``snapshot-gigabytes`` (total size of snapshots allowed),
``replica_gigabytes`` (requires API version 2.53) or ``per_share_gigabytes``
(requires API version 2.62).

If these resource quotas are not set by an administrator, default quotas
that are hardcoded in the service will apply. To view these
default quotas, the administrator can use the :command:`manila
quota-defaults` command:

.. code-block:: console

   $ manila quota-defaults
   +-----------------------+------------------------------------+
   | Property              | Value                              |
   +-----------------------+------------------------------------+
   | id                    | 1cc2154937bd40f4815d5f168d372263   |
   | gigabytes             | 1000                               |
   | per_share_gigabytes   | -1                                 |
   | snapshot_gigabytes    | 1000                               |
   | snapshots             | 50                                 |
   | shares                | 50                                 |
   | share_networks        | 10                                 |
   | share_groups          | 50                                 |
   | share_group_snapshots | 50                                 |
   | share_replicas        | 100                                |
   | replica_gigabytes     | 1000                               |
   +-----------------------+------------------------------------+

Administrators can modify default quotas with the :command:`manila
quota-class-update` command:

.. code-block:: console

    manila quota-class-update default \
        --shares 30                   \
        --snapshots 50                \
        --share-groups 15


Alternatively, you can also specify these defaults via the ``manila.conf``.
The following is an example:

.. code-block:: ini

    [quota]
    shares = 30
    share_gigabytes = 10000
    share_networks = 50
    share_snapshots = 100

.. important::

    Default quotas specified via the API will always take precedence over
    any defaults applied via ``manila.conf``. Therefore it is recommended to
    always use the API when creating or manipulating default quotas.


Custom quotas
~~~~~~~~~~~~~

The administrator can customize quotas for a specific project, or for a
specific user within a project context, or for a share type used by users of
a project.

To list the quotas for a project or user, use the :command:`manila quota-show`
command. If you specify the optional ``--user`` parameter, you get the
quotas for this user in the specified project. If you omit this parameter,
you get the quotas for the specified project. If there are no overrides, the
quotas shown will match the defaults.

.. note::

   The Shared File Systems service does not perform mapping of usernames and
   project names to IDs. Provide only ID values to get correct setup
   of quotas. Setting it by names you set quota for nonexistent project/user.
   In case quota is not set explicitly by project/user ID,
   The Shared File Systems service just applies default quotas.

.. code-block:: console

   $ manila quota-show --tenant %project_id% --user %user_id%
   +-----------------------+-----------------------------------+
   | Property              | Value                             |
   +-----------------------+-----------------------------------+
   | id                    | d99c76b43b1743fd822d26ccc915989c  |
   | gigabytes             | 1000                              |
   | per_share_gigabytes   | -1                                |
   | snapshot_gigabytes    | 1000                              |
   | snapshots             | 50                                |
   | shares                | 50                                |
   | share_networks        | 10                                |
   | share_groups          | 50                                |
   | share_group_snapshots | 50                                |
   | share_replicas        | 100                               |
   | replica_gigabytes     | 1000                              |
   +-----------------------+-----------------------------------+

These quotas can be updated with the :command:`manila quota-update` command.

.. code-block:: console

   $ manila quota-update %project_id% --user %user_id% --shares 49 --snapshots 49

The service will prevent the quota being set lower than the current
consumption. However, a quota update can still be made if necessary with
the``force`` key.

.. code-block:: console

   $ manila quota-update %project_id% --shares 51 --snapshots 51 --force

The administrator can also update the quotas for a specific share type. Share
Type quotas cannot be set for individual users within a project. They can only
be applied across all users of a particular project.

.. code-block:: console

   $ manila quota-update %project_id% --share-type %share_type_id%

To revert quotas to default for a project or for a user, simply delete
the quota that has been set:

.. code-block:: console

   $ manila quota-delete --tenant %project_id% --user-id %user_id%

Share type quotas can be reverted in the same way. Except, Share Type quotas
can not be set for individual users within a project, so they cannot be
unset either.

.. code-block:: console

   $ manila quota-delete --tenant %project_id% --share-type %share_type_id%
