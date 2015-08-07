#    Copyright 2014 Red Hat, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import textwrap

import mock
import pep8
import six
import testtools

from manila.hacking import checks
from manila import test


class HackingTestCase(test.TestCase):
    """Hacking test cases

    This class tests the hacking checks in manila.hacking.checks by passing
    strings to the check methods like the pep8/flake8 parser would. The parser
    loops over each line in the file and then passes the parameters to the
    check method. The parameter names in the check method dictate what type of
    object is passed to the check method. The parameter types are::

        logical_line: A processed line with the following modifications:
            - Multi-line statements converted to a single line.
            - Stripped left and right.
            - Contents of strings replaced with "xxx" of same length.
            - Comments removed.
        physical_line: Raw line of text from the input file.
        lines: a list of the raw lines from the input file
        tokens: the tokens that contribute to this logical line
        line_number: line number in the input file
        total_lines: number of lines in the input file
        blank_lines: blank lines before this one
        indent_char: indentation character in this file (" " or "\t")
        indent_level: indentation (with tabs expanded to multiples of 8)
        previous_indent_level: indentation on previous line
        previous_logical: previous logical line
        filename: Path of the file being run through pep8

    When running a test on a check method the return will be False/None if
    there is no violation in the sample input. If there is an error a tuple is
    returned with a position in the line, and a message. So to check the result
    just assertTrue if the check is expected to fail and assertFalse if it
    should pass.
    """

    def test_no_translate_debug_logs(self):
        self.assertEqual(len(list(checks.no_translate_debug_logs(
            "LOG.debug(_('foo'))", "manila/scheduler/foo.py"))), 1)

        self.assertEqual(len(list(checks.no_translate_debug_logs(
            "LOG.debug('foo')", "manila/scheduler/foo.py"))), 0)

        self.assertEqual(len(list(checks.no_translate_debug_logs(
            "LOG.info(_('foo'))", "manila/scheduler/foo.py"))), 0)

    def test_check_explicit_underscore_import(self):
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "LOG.info(_('My info message'))",
            "cinder/tests/other_files.py"))), 1)
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "cinder/tests/other_files.py"))), 1)
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "from cinder.i18n import _",
            "cinder/tests/other_files.py"))), 0)
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "LOG.info(_('My info message'))",
            "cinder/tests/other_files.py"))), 0)
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "cinder/tests/other_files.py"))), 0)
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "from cinder.i18n import _, _LW",
            "cinder/tests/other_files2.py"))), 0)
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "cinder/tests/other_files2.py"))), 0)
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "_ = translations.ugettext",
            "cinder/tests/other_files3.py"))), 0)
        self.assertEqual(len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "cinder/tests/other_files3.py"))), 0)

    # We are patching pep8 so that only the check under test is actually
    # installed.
    @mock.patch('pep8._checks',
                {'physical_line': {}, 'logical_line': {}, 'tree': {}})
    def _run_check(self, code, checker, filename=None):
        pep8.register_check(checker)

        lines = textwrap.dedent(code).strip().splitlines(True)

        checker = pep8.Checker(filename=filename, lines=lines)
        checker.check_all()
        checker.report._deferred_print.sort()
        return checker.report._deferred_print

    def _assert_has_errors(self, code, checker, expected_errors=None,
                           filename=None):
        actual_errors = [e[:3] for e in
                         self._run_check(code, checker, filename)]
        self.assertEqual(expected_errors or [], actual_errors)

    @testtools.skipIf(six.PY3, "It is PY2-specific. Skip it for PY3.")
    def test_str_exception(self):

        checker = checks.CheckForStrExc
        code = """
               def f(a, b):
                   try:
                       p = str(a) + str(b)
                   except ValueError as e:
                       p = str(e)
                   return p
               """
        errors = [(5, 16, 'M325')]
        self._assert_has_errors(code, checker, expected_errors=errors)

        code = """
               def f(a, b):
                   try:
                       p = str(a) + str(b)
                   except ValueError as e:
                       p = unicode(e)
                   return p
               """
        errors = []
        self._assert_has_errors(code, checker, expected_errors=errors)

        code = """
               def f(a, b):
                   try:
                       p = str(a) + str(b)
                   except ValueError as e:
                       try:
                           p  = unicode(a) + unicode(b)
                       except ValueError as ve:
                           p = str(e) + str(ve)
                       p = unicode(e)
                   return p
               """
        errors = [(8, 20, 'M325'), (8, 29, 'M325')]
        self._assert_has_errors(code, checker, expected_errors=errors)

    def test_trans_add(self):

        checker = checks.CheckForTransAdd
        code = """
               def fake_tran(msg):
                   return msg


               _ = fake_tran
               _LI = _
               _LW = _
               _LE = _
               _LC = _


               def f(a, b):
                   msg = _('test') + 'add me'
                   msg = _LI('test') + 'add me'
                   msg = _LW('test') + 'add me'
                   msg = _LE('test') + 'add me'
                   msg = _LC('test') + 'add me'
                   msg = 'add to me' + _('test')
                   return msg
               """
        if six.PY2:
            errors = [(13, 10, 'M326'), (14, 10, 'M326'), (15, 10, 'M326'),
                      (16, 10, 'M326'), (17, 10, 'M326'), (18, 24, 'M326')]
        else:
            errors = [(13, 11, 'M326'), (14, 13, 'M326'), (15, 13, 'M326'),
                      (16, 13, 'M326'), (17, 13, 'M326'), (18, 25, 'M326')]
        self._assert_has_errors(code, checker, expected_errors=errors)

        code = """
               def f(a, b):
                   msg = 'test' + 'add me'
                   return msg
               """
        errors = []
        self._assert_has_errors(code, checker, expected_errors=errors)
