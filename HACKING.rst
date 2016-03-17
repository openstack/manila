Manila Style Commandments
=======================

- Step 1: Read the OpenStack Style Commandments
  http://docs.openstack.org/developer/hacking/
- Step 2: Read on


Manila Specific Commandments
----------------------------

- [M319] Validate that debug level logs are not translated.
- [M323] Ensure that the _() function is explicitly imported to ensure proper translations.
- [M325] str() cannot be used on an exception.  Remove use or use six.text_type()
- [M326] Translated messages cannot be concatenated.  String should be
  included in translated message.
- [M328] LOG.critical messages require translations _LC()!
- [M328] LOG.error and LOG.exception messages require translations _LE()!
- [M329] LOG.info messages require translations _LI()!
- [M330] LOG.warning messages require translations _LW()!
- [M331] Log messages require translations!
- [M333] 'oslo_' should be used instead of 'oslo.'
- [M336] Must use a dict comprehension instead of a dict constructor
  with a sequence of key-value pairs.
- [M337] Ensure to not use xrange().

LOG Translations
----------------

LOG.debug messages will not get translated. Use  ``_LI()`` for
``LOG.info``, ``_LW`` for ``LOG.warning``, ``_LE`` for ``LOG.error``
and ``LOG.exception``, and ``_LC()`` for ``LOG.critical``.

``_()`` is preferred for any user facing message, even if it is also
going to a log file.  This ensures that the translated version of the
message will be available to the user.

The log marker functions (``_LI()``, ``_LW()``, ``_LE()``, and ``_LC()``)
must only be used when the message is only sent directly to the log.
Anytime that the message will be passed outside of the current context
(for example as part of an exception) the ``_()`` marker function
must be used.

A common pattern is to define a single message object and use it more
than once, for the log call and the exception.  In that case, ``_()``
must be used because the message is going to appear in an exception that
may be presented to the user.

For more details about translations, see
http://docs.openstack.org/developer/oslo.i18n/guidelines.html

Creating Unit Tests
-------------------
For every new feature, unit tests should be created that both test and
(implicitly) document the usage of said feature. If submitting a patch for a
bug that had no unit test, a new passing unit test should be added. If a
submitted bug fix does have a unit test, be sure to add a new one that fails
without the patch and passes with the patch.

For more information on creating unit tests and utilizing the testing
infrastructure in OpenStack Manila, please read manila/testing/README.rst.


openstack-common
----------------

A number of modules from openstack-common are imported into the project.

These modules are "incubating" in openstack-common and are kept in sync
with the help of openstack-common's update.py script. See:

  http://wiki.openstack.org/CommonLibrary#Incubation

The copy of the code should never be directly modified here. Please
always update openstack-common first and then run the script to copy
the changes across.


Running Tests
-------------
The testing system is based on a combination of tox and testr. If you just
want to run the whole suite, run `tox` and all will be fine. However, if
you'd like to dig in a bit more, you might want to learn some things about
testr itself. A basic walkthrough for OpenStack can be found at
http://wiki.openstack.org/testr


OpenStack Trademark
-------------------

OpenStack is a registered trademark of OpenStack, LLC, and uses the
following capitalization:

   OpenStack


Commit Messages
---------------
Using a common format for commit messages will help keep our git history
readable. Follow these guidelines:

  First, provide a brief summary (it is recommended to keep the commit title
  under 50 chars).

  The first line of the commit message should provide an accurate
  description of the change, not just a reference to a bug or
  blueprint. It must be followed by a single blank line.

  If the change relates to a specific driver (libvirt, xenapi, qpid, etc...),
  begin the first line of the commit message with the driver name, lowercased,
  followed by a colon.

  Following your brief summary, provide a more detailed description of
  the patch, manually wrapping the text at 72 characters. This
  description should provide enough detail that one does not have to
  refer to external resources to determine its high-level functionality.

  Once you use 'git review', two lines will be appended to the commit
  message: a blank line followed by a 'Change-Id'. This is important
  to correlate this commit with a specific review in Gerrit, and it
  should not be modified.

For further information on constructing high quality commit messages,
and how to split up commits into a series of changes, consult the
project wiki:

   http://wiki.openstack.org/GitCommitMessages
