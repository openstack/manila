========
Glossary
========

.. glossary::

  manila
   OpenStack project to provide "Shared Filesystems as a service".

  manila-api
   Service that provides a stable RESTful API.
   The service authenticates and routes requests throughout the Shared Filesystem service.
   There is :term:`python-manilaclient` to interact with the API.

  python-manilaclient
   Command line interface to interact with :term:`manila` via :term:`manila-api` and also a
   Python module to interact programmatically with :term:`manila`.

  manila-scheduler
   Responsible for scheduling/routing requests to the appropriate :term:`manila-share` service.
   It does that by picking one back-end while filtering all except one back-end.

  manila-share
   Responsible for managing Shared File Service devices, specifically the back-end devices.

  DHSS
   Acronym for 'driver handles share servers'. It defines two different share driver modes
   when they either do handle share servers or not. Each driver is allowed to work only in
   one mode at once. Requirement is to support, at least, one mode.

  replication_type
   Type of replication supported by a share driver. If the share driver supports replication
   it will report a valid value to the :term:`manila-scheduler`. The value of this
   capability can be one of :term:`readable`, :term:`writable` or :term:`dr`.

  readable
   A type of replication supported by :term:`manila` in which there is one :term:`active`
   replica (also referred to as `primary` share) and one or more non-active replicas (also
   referred to as `secondary` shares). All share replicas have at least one export location
   and are mountable. However, the non-active replicas cannot be written to until after
   promotion.

  writable
   A type of replication supported by :term:`manila` in which all share replicas are
   writable. There is no requirement of a promotion since replication is synchronous.
   All share replicas have one or more export locations each and are mountable.

  dr
   Acronym for `Disaster Recovery`. It is a type of replication supported by :term:`manila`
   in which there is one :term:`active` replica (also referred to as `primary` share) and
   one or more non-active replicas (also referred to as `secondary` shares). Only the
   `active` replica has one or more export locations and can be mounted. The non-active
   replicas are inaccessible until after promotion.

  active
   In :term:`manila`, an `active` replica refers to a share that can be written to. In
   `readable` and `dr` styles of replication, there is only one `active` replica at any given
   point in time. Thus, it may also be referred to as the `primary` share. In `writable`
   style of replication, all replicas are writable and there may be no distinction of a
   `primary` share.

  replica_state
   An attribute of the Share Instance (Share Replica) model in :term:`manila`. If the value is
   :term:`active`, it refers to the type of the replica. If the value is one of `in_sync` or
   `out_of_sync`, it refers to the state of consistency of data between the :term:`active`
   replica and the share replica. If the value is `error`, a potentially irrecoverable
   error may have occurred during the update of data between the :term:`active` replica and
   the share replica.

  replication_change
   State of a non-active replica when it is being promoted to become the :term:`active`
   replica.

  recovery point objective
   Abbreviated as ``RPO``, recovery point objective is a target window of time between which
   a storage backend may guarantee that data is consistent between a primary and a secondary
   replica. This window is **not** managed by :term:`manila`.


