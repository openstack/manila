=============
manila-manage
=============

-------------------------------------
control and manage shared filesystems
-------------------------------------

:Author: openstack-discuss@lists.openstack.org
:Copyright: OpenStack LLC
:Manual section: 1
:Manual group: shared filesystems

SYNOPSIS
========

  manila-manage <category> <action> [<args>]

DESCRIPTION
===========

manila-manage controls shared filesystems service.
More information about OpenStack Manila is at https://wiki.openstack.org/wiki/Manila

OPTIONS
=======

The standard pattern for executing a manila-manage command is:
``manila-manage <category> <command> [<args>]``

For example, to obtain a list of all hosts:
``manila-manage host list``

Run without arguments to see a list of available command categories:
``manila-manage``

Categories are shell, logs, service, db, host, version, config, share, and share_server.

Global Options
==============

``--config-dir DIR``
    Path to a config directory to pull `*.conf` files from. The set is parsed after `--config-file` arguments.

``--config-file PATH``
    Path to a config file to use. Multiple config files can be specified, with values in later files taking precedence.

``--debug, -d``
    Set logging level to DEBUG instead of the default INFO level.

``--log-config-append PATH``
    Append a logging configuration file. If set, other logging options are ignored.

``--log-date-format DATE_FORMAT``
    Defines the format string for %(asctime)s in log records.

``--log-dir LOG_DIR``
    The base directory used for relative log_file paths.

``--log-file PATH``
    Name of the log file to send logging output to.

``--use-journal / --nouse-journal``
    Enable or disable journald for logging.

``--use-json / --nouse-json``
    Enable or disable JSON formatting for logs.

``--use-syslog / --nouse-syslog``
    Enable or disable syslog for logging.

``--watch-log-file / --nowatch-log-file``
    Monitor log file changes.

``--shell_completion SHELL_COMPLETION``
    Display a shell completion script (allowed values: bash, zsh).

``--state_path STATE_PATH``
    Top-level directory for maintaining Manila's state.

``--syslog-log-facility SYSLOG_LOG_FACILITY``
    Syslog facility to receive log lines.

``--version``
    Show program version and exit.

Manila Db
~~~~~~~~~
``manila-manage db version``
    Print the current database version.

``manila-manage db sync``
    Sync the database up to the most recent version. This is the standard way to create the db as well.

``manila-manage db downgrade <version>``
    Downgrade database to given version.

``manila-manage db stamp <version>``
    Stamp database with given version.

``manila-manage db revision <message> <autogenerate>``
    Generate new migration.

``manila-manage db purge <age_in_days>``
    Purge deleted rows older than a given age from Manila database tables.
    If age_in_days is not given or is specified as 0 all available rows will
    be deleted.

Manila Logs
~~~~~~~~~~~
``manila-manage logs errors``
    Displays Manila errors from log files.

``manila-manage logs syslog <number>``
    Displays Manila alerts from syslog.

Manila Shell
~~~~~~~~~~~~
``manila-manage shell bpython``
    Starts a new bpython shell.

``manila-manage shell ipython``
    Starts a new ipython shell.

``manila-manage shell python``
    Starts a new python shell.

``manila-manage shell run``
    Starts a new shell using python.

``manila-manage shell script <path/scriptname>``
    Runs the named script from the specified path with flags set.

Manila Host
~~~~~~~~~~~
``manila-manage host list``
    Returns list of running Manila hosts.

Manila Config
~~~~~~~~~~~~~
``manila-manage config list``
    Returns list of currently set config options and their values.

Manila Service
~~~~~~~~~~~~~~
``manila-manage service list [--format_output table|json|yaml]``
    Returns list of Manila services. Output format can be modified using `--format_output`. It can be `table`, `json`, or `yaml`. Defaults to `table`.

Manila Version
~~~~~~~~~~~~~~
``manila-manage version list``
    Returns list of versions.

Manila Share
~~~~~~~~~~~~
``manila-manage share delete <share_id>``
    Deletes a specific share by ID.

``manila-manage share update_host [-h] --currenthost CURRENTHOST --newhost NEWHOST [--force FORCE]``
    Update the ``host`` attribute within a share. This can be used to alter existing
    share records if the backend or host name has been updated in manila configuration.
    A fully qualified host string is of the format 'HostA@BackendB#PoolC'.
    Provide only the host name (ex: 'HostA') to update the hostname part of the host string.
    Provide only the host name and backend name (ex: 'HostA@BackendB') to update the host and backend names.
    ``--force`` parameter can be used to skip validations.


Manila Share Server
~~~~~~~~~~~~~~~~~~~
``manila-manage share_server update_share_server_capabilities [-h] --share_servers SHARE_SERVERS --capabilities CAPABILITIES [--value VALUE]``
   Set share server boolean capabilities such as `security_service_update_support` and `network_allocation_update_support`.


FILES
=====
The manila-manage.conf file contains configuration information in the form of parameter settings.

BUGS
====
* Manila's bug tracker is on Launchpad. You can view current bugs and file new bugs on `OpenStack Manila Bug Tracker <https://bugs.launchpad.net/manila>`_



