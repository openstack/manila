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

import itertools
import sys
import textwrap

import ddt
import mock
import pep8

from manila.hacking import checks
from manila import test


@ddt.ddt
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

    @ddt.data(*itertools.product(
        ('', '_', '_LE', '_LI', '_LW'),
        ('audit', 'debug', 'error', 'info', 'warn', 'warning', 'critical',
         'exception',)))
    @ddt.unpack
    def test_no_translate_logs(self, log_marker, log_method):
        code = "LOG.{0}({1}('foo'))".format(log_method, log_marker)

        if log_marker:
            self.assertEqual(1, len(list(checks.no_translate_logs(code))))
        else:
            self.assertEqual(0, len(list(checks.no_translate_logs(code))))

    def test_check_explicit_underscore_import(self):
        self.assertEqual(1, len(list(checks.check_explicit_underscore_import(
            "LOG.info(_('My info message'))",
            "manila/tests/other_files.py"))))
        self.assertEqual(1, len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "manila/tests/other_files.py"))))
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "from manila.i18n import _",
            "manila/tests/other_files.py"))))
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "LOG.info(_('My info message'))",
            "manila/tests/other_files.py"))))
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "manila/tests/other_files.py"))))
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "from manila.i18n import _LE, _, _LW",
            "manila/tests/other_files2.py"))))
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "manila/tests/other_files2.py"))))
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "_ = translations.ugettext",
            "manila/tests/other_files3.py"))))
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "manila/tests/other_files3.py"))))
        # Complete code coverage by falling through all checks
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "LOG.info('My info message')",
            "manila.tests.unit/other_files4.py"))))
        self.assertEqual(0, len(list(checks.check_explicit_underscore_import(
            "from manila.i18n import _LW",
            "manila.tests.unit/other_files5.py"))))
        self.assertEqual(1, len(list(checks.check_explicit_underscore_import(
            "msg = _('My message')",
            "manila.tests.unit/other_files5.py"))))

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

    def _assert_has_no_errors(self, code, checker, filename=None):
        self._assert_has_errors(code, checker, filename=filename)

    def test_logging_format_no_tuple_arguments(self):
        checker = checks.CheckLoggingFormatArgs
        code = """
               import logging
               LOG = logging.getLogger()
               LOG.info("Message without a second argument.")
               LOG.critical("Message with %s arguments.", 'two')
               LOG.debug("Volume %s caught fire and is at %d degrees C and"
                         " climbing.", 'volume1', 500)
               """
        self._assert_has_no_errors(code, checker)

    @ddt.data(*checks.CheckLoggingFormatArgs.LOG_METHODS)
    def test_logging_with_tuple_argument(self, log_method):
        checker = checks.CheckLoggingFormatArgs
        code = """
               import logging
               LOG = logging.getLogger()
               LOG.{0}("Volume %s caught fire and is at %d degrees C and "
                      "climbing.", ('volume1', 500))
               """
        self._assert_has_errors(code.format(log_method), checker,
                                expected_errors=[(4, 21, 'M310')])

    def test_str_on_exception(self):

        checker = checks.CheckForStrUnicodeExc
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

    def test_no_str_unicode_on_exception(self):
        checker = checks.CheckForStrUnicodeExc
        code = """
               def f(a, b):
                   try:
                       p = unicode(a) + str(b)
                   except ValueError as e:
                       p = e
                   return p
               """
        self._assert_has_no_errors(code, checker)

    def test_unicode_on_exception(self):
        checker = checks.CheckForStrUnicodeExc
        code = """
               def f(a, b):
                   try:
                       p = str(a) + str(b)
                   except ValueError as e:
                       p = unicode(e)
                   return p
               """
        errors = [(5, 20, 'M325')]
        self._assert_has_errors(code, checker, expected_errors=errors)

    def test_str_on_multiple_exceptions(self):
        checker = checks.CheckForStrUnicodeExc
        code = """
               def f(a, b):
                   try:
                       p = str(a) + str(b)
                   except ValueError as e:
                       try:
                           p  = unicode(a) + unicode(b)
                       except ValueError as ve:
                           p = str(e) + str(ve)
                       p = e
                   return p
               """
        errors = [(8, 20, 'M325'), (8, 29, 'M325')]
        self._assert_has_errors(code, checker, expected_errors=errors)

    def test_str_unicode_on_multiple_exceptions(self):
        checker = checks.CheckForStrUnicodeExc
        code = """
               def f(a, b):
                   try:
                       p = str(a) + str(b)
                   except ValueError as e:
                       try:
                           p  = unicode(a) + unicode(b)
                       except ValueError as ve:
                           p = str(e) + unicode(ve)
                       p = str(e)
                   return p
               """
        errors = [(8, 20, 'M325'), (8, 33, 'M325'), (9, 16, 'M325')]
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

        # Python 3.4.0 introduced a change to the column calculation during AST
        # parsing. This was reversed in Python 3.4.3, hence the version-based
        # expected value calculation. See #1499743 for more background.
        if sys.version_info < (3, 4, 0) or sys.version_info >= (3, 4, 3):
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

    def test_dict_constructor_with_list_copy(self):
        self.assertEqual(1, len(list(checks.dict_constructor_with_list_copy(
            "    dict([(i, connect_info[i])"))))

        self.assertEqual(1, len(list(checks.dict_constructor_with_list_copy(
            "    attrs = dict([(k, _from_json(v))"))))

        self.assertEqual(1, len(list(checks.dict_constructor_with_list_copy(
            "        type_names = dict((value, key) for key, value in"))))

        self.assertEqual(1, len(list(checks.dict_constructor_with_list_copy(
            "   dict((value, key) for key, value in"))))

        self.assertEqual(1, len(list(checks.dict_constructor_with_list_copy(
            "foo(param=dict((k, v) for k, v in bar.items()))"))))

        self.assertEqual(1, len(list(checks.dict_constructor_with_list_copy(
            " dict([[i,i] for i in range(3)])"))))

        self.assertEqual(1, len(list(checks.dict_constructor_with_list_copy(
            "  dd = dict([i,i] for i in range(3))"))))

        self.assertEqual(0, len(list(checks.dict_constructor_with_list_copy(
            "        create_kwargs = dict(snapshot=snapshot,"))))

        self.assertEqual(0, len(list(checks.dict_constructor_with_list_copy(
            "      self._render_dict(xml, data_el, data.__dict__)"))))

    def test_no_xrange(self):
        self.assertEqual(1, len(list(checks.no_xrange("xrange(45)"))))

        self.assertEqual(0, len(list(checks.no_xrange("range(45)"))))

    def test_validate_assertTrue(self):
        test_value = True
        self.assertEqual(0, len(list(checks.validate_assertTrue(
            "assertTrue(True)"))))
        self.assertEqual(1, len(list(checks.validate_assertTrue(
            "assertEqual(True, %s)" % test_value))))

    def test_check_uuid4(self):
        code = """
            fake_uuid = uuid.uuid4()
               """
        errors = [(1, 0, 'M354')]
        self._assert_has_errors(code, checks.check_uuid4,
                                expected_errors=errors)

        code = """
               hex_uuid = uuid.uuid4().hex
               """
        self._assert_has_no_errors(code, checks.check_uuid4)

    def test_no_log_warn_check(self):
        self.assertEqual(0, len(list(checks.no_log_warn_check(
            "LOG.warning('This should not trigger LOG.warn "
            "hacking check.')"))))
        self.assertEqual(1, len(list(checks.no_log_warn_check(
            "LOG.warn('We should not use LOG.warn')"))))
        foo = """
            LOG.warn('Catch me too, please'
            )
            """
        self.assertEqual(1, len(list(checks.no_log_warn_check(foo))))
