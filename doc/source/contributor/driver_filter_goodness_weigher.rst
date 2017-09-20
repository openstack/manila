.. _driver_filter_goodness_weigher:

==========================================================
Configure and use driver filter and weighing for scheduler
==========================================================

OpenStack manila enables you to choose a share back end based on
back-end specific properties by using the DriverFilter and
GoodnessWeigher for the scheduler. The driver filter and weigher
scheduling can help ensure that the scheduler chooses the best back end
based on requested share properties as well as various back-end
specific properties.

What is driver filter and weigher and when to use it
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The driver filter and weigher give you the ability to more finely
control how manila scheduler chooses the best back
end to use when handling a share provisioning request. One example scenario
where using the driver filter and weigher can be if a back end that utilizes
thin-provisioning is used. The default filters use the ``free capacity``
property to determine the best back end, but that is not always perfect.
If a back end has the ability to provide a more accurate back-end
specific value, it can be used as part of the weighing process to find the
best possible host for a new share. Some more examples of the use of these
filters could be with respect to back end specific limitations. For example,
some back ends may be limited by the number of shares that can be created on
them, or by the minimum or maximum size allowed per share or by the fact that
provisioning beyond a particular capacity affects their performance. The
driver filter and weigher can provide a way for these limits to be accounted
for during scheduling.


Defining your own filter and goodness functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can define your own filter and goodness functions through the use of
various capabilities that manila exposes. Capabilities
exposed include information about the share request being made,
``share_type`` settings, and back-end specific information about drivers.
All of these allow for a lot of control over how the ideal back end for
a share request will be decided.

The ``filter_function`` option is a string defining a function that
will determine whether a back end should be considered as a potential
candidate by the scheduler.

The ``goodness_function`` option is a string defining a function that
will rate the quality of the potential host (0 to 100, 0 lowest, 100
highest).

.. important::

   The driver filter and weigher will use default values for filter and
   goodness functions for each back end if you do not define them
   yourself. If complete control is desired then a filter and goodness
   function should be defined for each of the back ends in
   the ``manila.conf`` file.


Supported operations in filter and goodness functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Below is a table of all the operations currently usable in custom filter
and goodness functions created by you:

+--------------------------------+-------------------------+
| Operations                     | Type                    |
+================================+=========================+
| +, -, \*, /, ^                 | standard math           |
+--------------------------------+-------------------------+
| not, and, or, &, \|, !         | logic                   |
+--------------------------------+-------------------------+
| >, >=, <, <=, ==, <>, !=       | equality                |
+--------------------------------+-------------------------+
| +, -                           | sign                    |
+--------------------------------+-------------------------+
| x ? a : b                      | ternary                 |
+--------------------------------+-------------------------+
| abs(x), max(x, y), min(x, y)   | math helper functions   |
+--------------------------------+-------------------------+

.. caution::

   Syntax errors in filter or goodness strings are thrown at a share creation
   time.

Available capabilities when creating custom functions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are various properties that can be used in either the
``filter_function`` or the ``goodness_function`` strings. The properties allow
access to share info, qos settings, extra specs, and so on.

The following capabilities are currently available for use:

Host capabilities for a back end
--------------------------------
host
    The host's name

share\_backend\_name
    The share back end name

vendor\_name
    The vendor name

driver\_version
    The driver version

storage\_protocol
    The storage protocol

qos
    Boolean signifying whether QoS is supported

total\_capacity\_gb
    The total capacity in gibibytes

allocated\_capacity\_gb
    The allocated capacity in gibibytes

free\_capacity\_gb
    The free capacity in gibibytes

reserved\_percentage
    The reserved storage percentage

driver\_handles\_share\_server
    The driver mode used by this host

thin\_provisioning
    Whether or not thin provisioning is supported by this host

updated
    Last time this host's stats were updated

dedupe
    Whether or not dedupe is supported by this host

compression
    Whether or not compression is supported by this host

snapshot\_support
    Whether or not snapshots are supported by this host

replication\_domain
    The replication domain of this host

replication\_type
    The replication type supported by this host

provisioned\_capacity\_gb
    The provisioned capacity of this host in gibibytes

pools
    This host's storage pools

max\_over\_subscription\_ratio
    This hosts's over subscription ratio for thin provisioning


Capabilities specific to a back end
-----------------------------------

These capabilities are determined by the specific back end
you are creating filter and goodness functions for. Some back ends
may not have any capabilities available here.

Requested share capabilities
----------------------------

availability\_zone\_id
    ID of the availability zone of this share

share\_network\_id
    ID of the share network used by this share

share\_server\_id
    ID of the share server of this share

host
    Host name of this share

is\_public
    Whether or not this share is public

snapshot\_support
    Whether or not snapshots are supported by this share

status
    Status for the requested share

share\_type\_id
    The share type ID

share\_id
    The share ID

user\_id
    The share's user ID

project\_id
    The share's project ID

id
    The share instance ID

replica\_state
    The share's replication state

replication\_type
    The replication type supported by this share

snapshot\_id
    The ID of the snapshot of which this share was created from

size
    The size of the share in gibibytes

share\_proto
    The protocol of this share

metadata
    General share metadata

The most used capability from this list will most likely be the ``size``.

Extra specs for the requested share type
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

View the available properties for share types by running:

.. code-block:: console

   $ manila extra-specs-list

Driver filter and weigher usage examples
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Below are examples for using the filter and weigher separately,
together, and using driver-specific properties.

Example ``manila.conf`` file configuration for customizing the filter
function:

.. code-block:: ini

   [default]
   enabled_backends = generic1, generic2

   [generic1]
   share_driver = manila.share.drivers.generic.GenericShareDriver
   share_backend_name = GENERIC1
   filter_function = "share.size < 10"

   [generic2]
   share_driver = manila.share.drivers.generic.GenericShareDriver
   share_backend_name = GENERIC2
   filter_function = "share.size >= 10"

The above example will filter share to different back ends depending
on the size of the requested share. Shares with a size less than 10 GB are
sent to generic1 and shares with a size greater than or equal to 10 GB are sent
to generic2.

Example ``manila.conf`` file configuration for customizing the goodness
function:

.. code-block:: ini

   [default]
   enabled_backends = generic1, generic2

   [generic1]
   share_driver = manila.share.drivers.generic.GenericShareDriver
   share_backend_name = GENERIC1
   goodness_function = "(share.size < 5) ? 100 : 50"

   [generic2]
   share_driver = manila.share.drivers.generic.GenericShareDriver
   share_backend_name = GENERIC2
   goodness_function = "(share.size >= 5) ? 100 : 25"

The above example will determine the goodness rating of a back end based
on the requested share's size. The example shows how the ternary if
statement can be used in a filter or goodness function. If a requested
share is of size 10 GB then generic1 is rated as 50 and generic2 is rated as
100. In this case generic2 wins. If a requested share is of size 3 GB then
generic1 is rated 100 and generic2 is rated 25. In this case generic1 would win.

Example ``manila.conf`` file configuration for customizing both the
filter and goodness functions:

.. code-block:: ini

   [default]
   enabled_backends = generic1, generic2

   [generic1]
   share_driver = manila.share.drivers.generic.GenericShareDriver
   share_backend_name = GENERIC1
   filter_function = "stats.total_capacity_gb < 500"
   goodness_function = "(share.size < 25) ? 100 : 50"

   [generic2]
   share_driver = manila.share.drivers.generic.GenericShareDriver
   share_backend_name = GENERIC2
   filter_function = "stats.total_capacity_gb >= 500"
   goodness_function = "(share.size >= 25) ? 100 : 75"

The above example combines the techniques from the first two examples.
The best back end is now decided based on the total capacity of the
back end and the requested share's size.

Example ``manila.conf`` file configuration for accessing driver specific
properties:

.. code-block:: ini

   [default]
   enabled_backends = example1, example2, example3

   [example1]
   share_driver = manila.share.drivers.example.ExampleShareDriver
   share_backend_name = EXAMPLE1
   filter_function = "share.size < 5"
   goodness_function = "(capabilities.provisioned_capacity_gb < 30) ? 100 : 50"

   [example2]
   share_driver = manila.share.drivers.example.ExampleShareDriver
   share_backend_name = EXAMPLE2
   filter_function = "shares.size < 5"
   goodness_function = "(capabilities.provisioned_capacity_gb < 80) ? 100 : 50"

   [example3]
   share_driver = manila.share.drivers.example.ExampleShareDriver
   share_backend_name = EXAMPLE3
   goodness_function = "55"

The above is an example of how back-end specific capabilities can be used
in the filter and goodness functions. In this example, the driver has a
``provisioned_capacity_gb`` capability that is being used to determine which
back end gets used during a share request. In the above example, ``example1``
and ``example2`` will handle share requests for all shares with a size less
than 5 GB. ``example1`` will have priority until the provisioned capacity of
all shares on it hits 30 GB. After that, ``example2`` will have priority until
the provisioned capacity of all shares on it hits 80 GB. ``example3`` will
collect all shares greater or equal to 5 GB as well as all shares once
``example1`` and ``example2`` lose priority.

