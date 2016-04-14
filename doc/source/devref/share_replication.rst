..
      Copyright (c) 2016 Goutham Pacha Ravi

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


=================
Share Replication
=================

As of the Mitaka release of OpenStack, :term:`manila` supports replication of
shares between different pools for drivers that operate with
``driver_handles_share_servers=False`` mode. These pools may be on different
backends or within the same backend. This feature can be used as a disaster
recovery solution or as a load sharing mirroring solution depending upon the
replication style chosen, the capability of the driver and the configuration
of backends.

This feature assumes and relies on the fact that share drivers will be
responsible for communicating with ALL storage controllers necessary to
achieve any replication tasks, even if that involves sending commands to
other storage controllers in other Availability Zones (or AZs).

End users would be able to create and manage their replicas, alongside their
shares and snapshots.


Storage availability zones and replication domains
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Replication is supported within the same availability zone, but in an ideal
solution, an Availability Zone should be perceived as a single failure domain.
So this feature provides the most value in an inter-AZ replication use case.

The ``replication_domain`` option is a backend specific StrOpt option to be
used within ``manila.conf``. The value can be any ASCII string. Two backends
that can replicate between each other would have the same
``replication_domain``. This comes from the premise that manila expects
Share Replication to be performed between backends that have similar
characteristics.

When scheduling new replicas, the scheduler takes into account the
``replication_domain`` option to match similar backends. It also ensures that
only one replica can be scheduled per pool. When backends report multiple
pools, manila would allow for replication between two pools on the same
backend.

The ``replication_domain`` option is meant to be used in conjunction with the
``storage_availability_zone`` option to utilize this solution for Data
Protection/Disaster Recovery.


Replication types
~~~~~~~~~~~~~~~~~

When creating a share that is meant to have replicas in the future, the user
will use a ``share_type`` with an extra_spec, :term:`replication_type` set to
a valid replication type that manila supports. Drivers must report the
replication type that they support as the :term:`replication_type`
capability during the ``_update_share_stats()`` call.

Three types of replication are currently supported:

**writable**
    Synchronously replicated shares where all replicas are writable.
    Promotion is not supported and not needed.

**readable**
    Mirror-style replication with a primary (writable) copy
    and one or more secondary (read-only) copies which can become writable
    after a promotion.

**dr (for Disaster Recovery)**
    Generalized replication with secondary copies that are inaccessible until
    they are promoted to become the ``active`` replica.

.. note::

    The term :term:`active` replica refers to the ``primary`` share. In
    :term:`writable` style of replication, all replicas are :term:`active`,
    and there could be no distinction of a ``primary`` share. In
    :term:`readable` and :term:`dr` styles of replication, a ``secondary``
    replica may be referred to as ``passive``, ``non-active`` or simply
    ``replica``.


Health of a share replica
~~~~~~~~~~~~~~~~~~~~~~~~~

Apart from the ``status`` attribute, share replicas have the
:term:`replica_state` attribute to denote the state of the replica. The
``primary`` replica will have it's :term:`replica_state` attribute set to
:term:`active`. A ``secondary`` replica may have one of the following values as
its :term:`replica_state`:

**in_sync**
    The replica is up to date with the active replica
    (possibly within a backend specific :term:`recovery point objective`).

**out_of_sync**
    The replica has gone out of date (all new replicas start out in this
    :term:`replica_state`).

**error**
    When the scheduler failed to schedule this replica or some potentially
    irrecoverable damage occurred with regard to updating data for this
    replica.

Manila requests periodic update of the :term:`replica_state` of all non-active
replicas. The update occurs with respect to an interval defined through the
``replica_state_update_interval`` option in ``manila.conf``.

Administrators have an option of initiating a ``resync`` of a secondary
replica (for :term:`readable` and :term:`dr` types of replication). This could
be performed before a planned failover operation in order to have the most
up-to-date data on the replica.


Promotion
~~~~~~~~~

For :term:`readable` and :term:`dr` styles, we refer to the task of
switching a ``non-active`` replica with the :term:`active` replica as
`promotion`. For the :term:`writable` style of replication, promotion does
not make sense since all replicas are :term:`active` (or writable) at all
given points of time.

The ``status`` attribute of the non-active replica being promoted will be set
to :term:`replication_change` during its promotion. This has been classified
as a ``busy`` state and hence API interactions with the share are restricted
while one of its replicas is in this state.

Promotion of replicas with :term:`replica_state` set to ``error`` may not be
fully supported by the backend. However, manila allows the action as an
administrator feature and such an attempt may be honored by backends if
possible.

When multiple replicas exist, multiple replication relationships
between shares may need to be redefined at the backend during the promotion
operation. If the driver fails at this stage, the replicas may be left in an
inconsistent state. The share manager will set all replicas to have the
``status`` attribute set to ``error``. Recovery from this state would require
administrator intervention.


Snapshots
~~~~~~~~~

If the driver supports snapshots, the replication of a snapshot is expected
to be initiated simultaneously with the creation of the snapshot on the
:term:`active` replica. Manila tracks snapshots across replicas as separate
snapshot instances. The aggregate snapshot object itself will be in
``creating`` state until it is ``available`` across all of the share's replicas
that have their :term:`replica_state` attribute set to :term:`active` or
``in_sync``.

Therefore, for a driver that supports snapshots, the definition of being
``in_sync`` with the primary is not only that data is ensured (within the
:term:`recovery point objective`), but also that any 'available' snapshots
on the primary are ensured on the replica as well. If the snapshots cannot
be ensured, the :term:`replica_state` *must* be reported to manila as being
``out_of_sync`` until the snapshots have been replicated.

When a snapshot instance has its ``status`` attribute set to ``creating`` or
``deleting``, manila will poll the respective drivers for a status update. As
described earlier, the parent snapshot itself will be ``available`` only when
its instances across the :term:`active` and ``in_sync`` replicas of the share
are ``available``. The polling interval will be the same as
``replica_state_update_interval``.


Access Rules
~~~~~~~~~~~~

Access rules are not meant to be different across the replicas of the share.
Manila expects drivers to handle these access rules effectively depending on
the style of replication supported. For example, the :term:`dr` style of
replication does mean that the non-active replicas are inaccessible, so if
read-write rules are expected, then the rules should be applied on the
:term:`active` replica only. Similarly, drivers that
support :term:`readable` replication type should apply any read-write
rules as read-only for the non-active replicas.

Drivers will receive all the access rules in ``create_replica``,
``delete_replica`` and ``update_replica_state`` calls and have ample
opportunity to reconcile these rules effectively across replicas.


Understanding Replication Workflows
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Creating a share that supports replication
------------------------------------------
Administrators can create a share type with extra-spec
:term:`replication_type`, matching the style of replication the desired backend
supports. Users can use the share type to create a new share that
allows/supports replication. A replicated share always starts out with one
replica, the ``primary`` share itself.

The :term:`manila-scheduler` service will filter and weigh available pools to
find a suitable pool for the share being created. In particular,

* The ``CapabilityFilter`` will match the :term:`replication_type` extra_spec
  in the request share_type with the ``replication_type`` capability reported
  by a pool.
* The ``ShareReplicationFilter`` will further ensure that the pool has a
  non-empty ``replication_domain`` capability being reported as well.
* The ``AvailabilityZoneFilter`` will ensure that the availability_zone
  requested matches with the pool's availability zone.

Creating a replica
------------------
The user has to specify the share name/id of the share that is supposed to be
replicated and optionally an availability zone for the replica to exist in.
The replica inherits the parent share's share_type and associated
extra_specs. Scheduling of the replica is similar to that of the share.

* The `ShareReplicationFilter` will ensure that the pool is within
    the same ``replication_domain`` as the :term:`active` replica and also
    ensures that the pool does not already have a replica for that share.

Drivers supporting :term:`writable` style **must** set the
:term:`replica_state` attribute to :term:`active` when the replica has been
created and is ``available``.

Deleting a replica
------------------
Users can remove replicas that have their `status` attribute set to
``error``, ``in_sync`` or ``out_of_sync``. They could even delete an
:term:`active` replica as long as there is another :term:`active` replica
(as could be the case with `writable` replication style). Before the
``delete_replica`` call is made to the driver, an update_access call is made
to ensure access rules are safely removed for the replica.

Administrators may also ``force-delete`` replicas. Any driver exceptions will
only be logged and not re-raised; the replica will be purged from manila's
database.

Promoting a replica
-------------------
Users can promote replicas that have their :term:`replica_state` attribute set
to ``in_sync``. Administrators can attempt to promote replicas that have their
:term:`replica_state` attribute set to ``out_of_sync`` or ``error``. During a
promotion, if the driver raises an exception, all replicas will have their
`status` attribute set to `error` and recovery from this state will require
administrator intervention.

Resyncing a replica
-------------------
Prior to a planned failover, an administrator could attempt to update the
data on the replica. The ``update_replica_state`` call will be made during
such an action, giving drivers an opportunity to push the latest updates from
the `active` replica to the secondaries.

Creating a snapshot
-------------------
When a user takes a snapshot of a share that has replicas, manila creates as
many snapshot instances as there are share replicas. These snapshot
instances all begin with their `status` attribute set to `creating`. The driver
is expected to create the snapshot of the ``active`` replica and then begin to
replicate this snapshot as soon as the :term:`active` replica's
snapshot instance is created and becomes ``available``.

Deleting a snapshot
-------------------
When a user deletes a snapshot, the snapshot instances corresponding to each
replica of the share have their ``status`` attribute set to ``deleting``.
Drivers must update their secondaries as soon as the :term:`active` replica's
snapshot instance is deleted.


Driver Interfaces
~~~~~~~~~~~~~~~~~

As part of the ``_update_share_stats()`` call, the base driver reports the
``replication_domain`` capability. Drivers are expected to update the
:term:`replication_type` capability.

Drivers must implement the methods enumerated below in order to support
replication. ``promote_replica``, ``update_replica_state`` and
``update_replicated_snapshot`` need not be implemented by drivers that support
the :term:`writable` style of replication. The snapshot methods
``create_replicated_snapshot``, ``delete_replicated_snapshot`` and
``update_replicated_snapshot`` need not be implemented by a driver that does
not support snapshots.

Each driver request is made on a specific host. Create/delete operations
on secondary replicas are always made on the destination host. Create/delete
operations on snapshots are always made on the :term:`active` replica's host.
``update_replica_state`` and ``update_replicated_snapshot`` calls are made on
the host that the replica or snapshot resides on.

Share Replica interfaces:
-------------------------

.. autoclass:: manila.share.driver.ShareDriver
    :members: create_replica, delete_replica, promote_replica, update_replica_state

Replicated Snapshot interfaces:
-------------------------------

.. autoclass:: manila.share.driver.ShareDriver
    :members:  create_replicated_snapshot, delete_replicated_snapshot, update_replicated_snapshot
