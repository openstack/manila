Manila Style Commandments
=========================

- Step 1: Read the OpenStack Style Commandments
  https://docs.openstack.org/hacking/latest/
- Step 2: Read on


Manila Specific Commandments
----------------------------

- [M310] Check for improper use of logging format arguments.
- [M313] Use assertTrue(...) rather than assertEqual(True, ...).
- [M323] Ensure that the _() function is explicitly imported to ensure proper translations.
- [M325] str() and unicode() cannot be used on an exception. Remove or use six.text_type().
- [M326] Translated messages cannot be concatenated.  String should be
  included in translated message.
- [M333] ``oslo_`` should be used instead of ``oslo.``
- [M336] Must use a dict comprehension instead of a dict constructor
  with a sequence of key-value pairs.
- [M337] Ensure to not use xrange().
- [M354] Use oslo_utils.uuidutils to generate UUID instead of uuid4().
- [M338] Ensure to not use LOG.warn().
- [M359] Validate that log messages are not translated.

LOG Translations
----------------

Beginning with the Pike series, OpenStack no longer supports log translation.
It is not useful to add translation instructions to new code, the
instructions can be removed from old code, and the hacking checks that
enforced use of special translation markers for log messages have been
removed.

Other user-facing strings, e.g. in exception messages, should be translated
using ``_()``.

A common pattern is to define a single message object and use it more
than once, for the log call and the exception.  In that case, ``_()``
must be used because the message is going to appear in an exception that
may be presented to the user.

For more details about translations, see
https://docs.openstack.org/oslo.i18n/latest/user/guidelines.html

Creating Unit Tests
-------------------
For every new feature, unit tests should be created that both test and
(implicitly) document the usage of said feature. If submitting a patch for a
bug that had no unit test, a new passing unit test should be added. If a
submitted bug fix does have a unit test, be sure to add a new one that fails
without the patch and passes with the patch.

For more information on creating unit tests and utilizing the testing
infrastructure in OpenStack Manila, please read manila/testing/README.rst.


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
