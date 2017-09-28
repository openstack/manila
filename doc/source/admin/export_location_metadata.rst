Export Location Metadata
========================
Manila shares can have one or more export locations. The exact number depends
on the driver and the storage controller, and there is no preference
for more or fewer export locations. Usually drivers create an export location
for each physical network interface through which the share can be accessed.

Because not all export locations have the same qualities, Manila allows
drivers to add additional keys to the dict returned for each export location
when a share is created. The share manager stores these extra keys and values
in the database and they are available to the API service, which may expose
them through the REST API or use them for filtering.

Metadata Keys
-------------
Only keys defined in this document are valid. Arbitrary driver-defined keys
are not allowed. The following keys are defined:

* `is_admin_only` - May be True or False. Defaults to False. Indicates
  that the export location exists for administrative purposes. If
  is_admin_only=True, then the export location is hidden from non-admin users
  calling the REST API. Also, these export locations are assumed to be
  reachable directly from the admin network, which is important for drivers
  that support share servers and which have some export locations only
  accessible to tenants.

* `preferred` - May be True or False. Defaults to False. Indicates that
  clients should prefer to mount this export location over other export
  locations that are not preferred. This may be used by drivers which have
  fast/slow paths to indicate to clients which paths are faster. It could be
  used to indicate a path is preferred for another reason, as long as the
  reason isn't one that changes over the life of the manila-share service.
  This key is always visible through the REST API.
