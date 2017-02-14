=============
manila-manage
=============

-------------------------------------
control and manage shared filesystems
-------------------------------------

:Author: openstack@lists.launchpad.net
:Date:   2014-06-11
:Copyright: OpenStack LLC
:Version: 2014.2
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

Categories are shell, logs, service, db, host, version and config. Detailed descriptions are below.

These sections describe the available categories and arguments for manila-manage.

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

    Purge deleted rows older than a given age from manila database tables.
    If age_in_days is not given or is specified as 0 all available rows will
    be deleted.

Manila Logs
~~~~~~~~~~~

``manila-manage logs errors``

    Displays manila errors from log files.

``manila-manage logs syslog <number>``

    Displays manila alerts from syslog.

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

    Returns list of running manila hosts.

Manila Config
~~~~~~~~~~~~~

``manila-manage config list``

    Returns list of currently set config options and its values.


Manila Service
~~~~~~~~~~~~~~

``manila-manage service list``

    Returns list of manila services.

Manila Version
~~~~~~~~~~~~~~

``manila-manage version list``

    Returns list of versions.

FILES
=====

The manila-manage.conf file contains configuration information in the form of python-gflags.

BUGS
====

* Manila is sourced in Launchpad so you can view current bugs at `OpenStack Manila <https://bugs.launchpad.net/manila>`__



