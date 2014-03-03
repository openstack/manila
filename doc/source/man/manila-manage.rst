===========
manila-manage
===========

------------------------------------------------------
control and manage cloud computer instances and images
------------------------------------------------------

:Author: openstack@lists.launchpad.net
:Date:   2012-04-05
:Copyright: OpenStack LLC
:Version: 2012.1
:Manual section: 1
:Manual group: cloud computing

SYNOPSIS
========

  manila-manage <category> <action> [<args>]

DESCRIPTION
===========

manila-manage controls cloud computing instances by managing manila users, manila projects, manila roles, shell selection, vpn connections, and floating IP address configuration. More information about OpenStack Manila is at http://manila.openstack.org.

OPTIONS
=======

The standard pattern for executing a manila-manage command is:
``manila-manage <category> <command> [<args>]``

For example, to obtain a list of all projects:
``manila-manage project list``

Run without arguments to see a list of available command categories:
``manila-manage``

Categories are user, project, role, shell, vpn, and floating. Detailed descriptions are below.

You can also run with a category argument such as user to see a list of all commands in that category:
``manila-manage user``

These sections describe the available categories and arguments for manila-manage.

Manila Db
~~~~~~~

``manila-manage db version``

    Print the current database version.

``manila-manage db sync``

    Sync the database up to the most recent version. This is the standard way to create the db as well.

Manila User
~~~~~~~~~

``manila-manage user admin <username>``

    Create an admin user with the name <username>.

``manila-manage user create <username>``

    Create a normal user with the name <username>.

``manila-manage user delete <username>``

    Delete the user with the name <username>.

``manila-manage user exports <username>``

    Outputs a list of access key and secret keys for user to the screen

``manila-manage user list``

    Outputs a list of all the user names to the screen.

``manila-manage user modify <accesskey> <secretkey> <admin?T/F>``

    Updates the indicated user keys, indicating with T or F if the user is an admin user. Leave any argument blank if you do not want to update it.

Manila Project
~~~~~~~~~~~~

``manila-manage project add <projectname>``

    Add a manila project with the name <projectname> to the database.

``manila-manage project create <projectname>``

    Create a new manila project with the name <projectname> (you still need to do manila-manage project add <projectname> to add it to the database).

``manila-manage project delete <projectname>``

    Delete a manila project with the name <projectname>.

``manila-manage project environment <projectname> <username>``

    Exports environment variables for the named project to a file named manilarc.

``manila-manage project list``

    Outputs a list of all the projects to the screen.

``manila-manage project quota <projectname>``

    Outputs the size and specs of the project's instances including gigabytes, instances, floating IPs, volumes, and cores.

``manila-manage project remove <projectname>``

    Deletes the project with the name <projectname>.

``manila-manage project zipfile``

    Compresses all related files for a created project into a zip file manila.zip.

Manila Role
~~~~~~~~~

``manila-manage role add <username> <rolename> <(optional) projectname>``

    Add a user to either a global or project-based role with the indicated <rolename> assigned to the named user. Role names can be one of the following five roles: cloudadmin, itsec, sysadmin, netadmin, developer. If you add the project name as the last argument then the role is assigned just for that project, otherwise the user is assigned the named role for all projects.

``manila-manage role has <username> <projectname>``
    Checks the user or project and responds with True if the user has a global role with a particular project.

``manila-manage role remove <username> <rolename>``
    Remove the indicated role from the user.

Manila Logs
~~~~~~~~~

``manila-manage logs errors``

    Displays manila errors from log files.

``manila-manage logs syslog <number>``

    Displays manila alerts from syslog.

Manila Shell
~~~~~~~~~~

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

Manila VPN
~~~~~~~~

``manila-manage vpn list``

    Displays a list of projects, their IP prot numbers, and what state they're in.

``manila-manage vpn run <projectname>``

    Starts the VPN for the named project.

``manila-manage vpn spawn``

    Runs all VPNs.

Manila Floating IPs
~~~~~~~~~~~~~~~~~

``manila-manage floating create <ip_range> [--pool <pool>] [--interface <interface>]``

    Creates floating IP addresses for the given range, optionally specifying
    a floating pool and a network interface.

``manila-manage floating delete <ip_range>``

    Deletes floating IP addresses in the range given.

``manila-manage floating list``

    Displays a list of all floating IP addresses.

Manila Flavor
~~~~~~~~~~~

``manila-manage flavor list``

    Outputs a list of all active flavors to the screen.

``manila-manage flavor list --all``

    Outputs a list of all flavors (active and inactive) to the screen.

``manila-manage flavor create <name> <memory> <vCPU> <local_storage> <flavorID> <(optional) swap> <(optional) RXTX Quota> <(optional) RXTX Cap>``

    creates a flavor with the following positional arguments:
     * memory (expressed in megabytes)
     * vcpu(s) (integer)
     * local storage (expressed in gigabytes)
     * flavorid (unique integer)
     * swap space (expressed in megabytes, defaults to zero, optional)
     * RXTX quotas (expressed in gigabytes, defaults to zero, optional)
     * RXTX cap (expressed in gigabytes, defaults to zero, optional)

``manila-manage flavor delete <name>``

    Delete the flavor with the name <name>. This marks the flavor as inactive and cannot be launched. However, the record stays in the database for archival and billing purposes.

``manila-manage flavor delete <name> --purge``

    Purges the flavor with the name <name>. This removes this flavor from the database.

Manila Instance_type
~~~~~~~~~~~~~~~~~~

The instance_type command is provided as an alias for the flavor command. All the same subcommands and arguments from manila-manage flavor can be used.

Manila Images
~~~~~~~~~~~

``manila-manage image image_register <path> <owner>``

    Registers an image with the image service.

``manila-manage image kernel_register <path> <owner>``

    Registers a kernel with the image service.

``manila-manage image ramdisk_register <path> <owner>``

    Registers a ramdisk with the image service.

``manila-manage image all_register <image_path> <kernel_path> <ramdisk_path> <owner>``

    Registers an image kernel and ramdisk with the image service.

``manila-manage image convert <directory>``

    Converts all images in directory from the old (Bexar) format to the new format.

Manila VM
~~~~~~~~~~~

``manila-manage vm list [host]``
    Show a list of all instances. Accepts optional hostname (to show only instances on specific host).

``manila-manage live-migration <ec2_id> <destination host name>``
    Live migrate instance from current host to destination host. Requires instance id (which comes from euca-describe-instance) and destination host name (which can be found from manila-manage service list).


FILES
========

The manila-manage.conf file contains configuration information in the form of python-gflags.

SEE ALSO
========

* `OpenStack Manila <http://manila.openstack.org>`__

BUGS
====

* Manila is sourced in Launchpad so you can view current bugs at `OpenStack Manila <http://manila.openstack.org>`__



