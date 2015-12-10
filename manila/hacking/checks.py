# Copyright (c) 2012, Cloudscaling
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import ast
import re

import pep8


"""
Guidelines for writing new hacking checks

 - Use only for Manila specific tests. OpenStack general tests
   should be submitted to the common 'hacking' module.
 - Pick numbers in the range M3xx. Find the current test with
   the highest allocated number and then pick the next value.
 - Keep the test method code in the source file ordered based
   on the M3xx value.
 - List the new rule in the top level HACKING.rst file
 - Add test cases for each new rule to manila/tests/test_hacking.py

"""

UNDERSCORE_IMPORT_FILES = []

log_translation = re.compile(
    r"(.)*LOG\.(audit|error|info|critical|exception)\(\s*('|\")")
log_translation_LC = re.compile(
    r"(.)*LOG\.(critical)\(\s*(_\(|'|\")")
log_translation_LE = re.compile(
    r"(.)*LOG\.(error|exception)\(\s*(_\(|'|\")")
log_translation_LI = re.compile(
    r"(.)*LOG\.(info)\(\s*(_\(|'|\")")
log_translation_LW = re.compile(
    r"(.)*LOG\.(warning|warn)\(\s*(_\(|'|\")")
translated_log = re.compile(
    r"(.)*LOG\.(audit|error|info|warn|warning|critical|exception)"
    "\(\s*_\(\s*('|\")")
string_translation = re.compile(r"[^_]*_\(\s*('|\")")
underscore_import_check = re.compile(r"(.)*import _(.)*")
# We need this for cases where they have created their own _ function.
custom_underscore_check = re.compile(r"(.)*_\s*=\s*(.)*")
oslo_namespace_imports = re.compile(r"from[\s]*oslo[.](.*)")
dict_constructor_with_list_copy_re = re.compile(r".*\bdict\((\[)?(\(|\[)")


class BaseASTChecker(ast.NodeVisitor):
    """Provides a simple framework for writing AST-based checks.

    Subclasses should implement visit_* methods like any other AST visitor
    implementation. When they detect an error for a particular node the
    method should call ``self.add_error(offending_node)``. Details about
    where in the code the error occurred will be pulled from the node
    object.

    Subclasses should also provide a class variable named CHECK_DESC to
    be used for the human readable error message.

    """

    CHECK_DESC = 'No check message specified'

    def __init__(self, tree, filename):
        """This object is created automatically by pep8.

        :param tree: an AST tree
        :param filename: name of the file being analyzed
                         (ignored by our checks)
        """
        self._tree = tree
        self._errors = []

    def run(self):
        """Called automatically by pep8."""
        self.visit(self._tree)
        return self._errors

    def add_error(self, node, message=None):
        """Add an error caused by a node to the list of errors for pep8."""
        message = message or self.CHECK_DESC
        error = (node.lineno, node.col_offset, message, self.__class__)
        self._errors.append(error)

    def _check_call_names(self, call_node, names):
        if isinstance(call_node, ast.Call):
            if isinstance(call_node.func, ast.Name):
                if call_node.func.id in names:
                    return True
        return False


def no_translate_debug_logs(logical_line, filename):
    """Check for 'LOG.debug(_('

    As per our translation policy,
    https://wiki.openstack.org/wiki/LoggingStandards#Log_Translation
    we shouldn't translate debug level logs.

    * This check assumes that 'LOG' is a logger.
    * Use filename so we can start enforcing this in specific folders instead
      of needing to do so all at once.

    M319
    """
    if logical_line.startswith("LOG.debug(_("):
        yield(0, "M319 Don't translate debug level logs")


def validate_log_translations(logical_line, physical_line, filename):
    # Translations are not required in the test and tempest
    # directories.
    if ("manila/tests" in filename or "manila_tempest_tests" in filename or
            "contrib/tempest" in filename):
        return
    if pep8.noqa(physical_line):
        return
    msg = "M327: LOG.critical messages require translations `_LC()`!"
    if log_translation_LC.match(logical_line):
        yield (0, msg)
    msg = ("M328: LOG.error and LOG.exception messages require translations "
           "`_LE()`!")
    if log_translation_LE.match(logical_line):
        yield (0, msg)
    msg = "M329: LOG.info messages require translations `_LI()`!"
    if log_translation_LI.match(logical_line):
        yield (0, msg)
    msg = "M330: LOG.warning messages require translations `_LW()`!"
    if log_translation_LW.match(logical_line):
        yield (0, msg)
    msg = "M331: Log messages require translations!"
    if log_translation.match(logical_line):
        yield (0, msg)


def check_explicit_underscore_import(logical_line, filename):
    """Check for explicit import of the _ function

    We need to ensure that any files that are using the _() function
    to translate logs are explicitly importing the _ function.  We
    can't trust unit test to catch whether the import has been
    added so we need to check for it here.
    """

    # Build a list of the files that have _ imported.  No further
    # checking needed once it is found.
    if filename in UNDERSCORE_IMPORT_FILES:
        pass
    elif (underscore_import_check.match(logical_line) or
          custom_underscore_check.match(logical_line)):
        UNDERSCORE_IMPORT_FILES.append(filename)
    elif (translated_log.match(logical_line) or
          string_translation.match(logical_line)):
        yield(0, "M323: Found use of _() without explicit import of _ !")


class CheckForStrExc(BaseASTChecker):
    """Checks for the use of str() on an exception.

    This currently only handles the case where str() is used in
    the scope of an exception handler.  If the exception is passed
    into a function, returned from an assertRaises, or used on an
    exception created in the same scope, this does not catch it.
    """

    CHECK_DESC = ('M325 str() cannot be used on an exception.  '
                  'Remove or use six.text_type()')

    def __init__(self, tree, filename):
        super(CheckForStrExc, self).__init__(tree, filename)
        self.name = []
        self.already_checked = []

    def visit_TryExcept(self, node):
        for handler in node.handlers:
            if handler.name:
                self.name.append(handler.name.id)
                super(CheckForStrExc, self).generic_visit(node)
                self.name = self.name[:-1]
            else:
                super(CheckForStrExc, self).generic_visit(node)

    def visit_Call(self, node):
        if self._check_call_names(node, ['str']):
            if node not in self.already_checked:
                self.already_checked.append(node)
                if isinstance(node.args[0], ast.Name):
                    if node.args[0].id in self.name:
                        self.add_error(node.args[0])
        super(CheckForStrExc, self).generic_visit(node)


class CheckForTransAdd(BaseASTChecker):
    """Checks for the use of concatenation on a translated string.

    Translations should not be concatenated with other strings, but
    should instead include the string being added to the translated
    string to give the translators the most information.
    """

    CHECK_DESC = ('M326 Translated messages cannot be concatenated.  '
                  'String should be included in translated message.')

    TRANS_FUNC = ['_', '_LI', '_LW', '_LE', '_LC']

    def visit_BinOp(self, node):
        if isinstance(node.op, ast.Add):
            if self._check_call_names(node.left, self.TRANS_FUNC):
                self.add_error(node.left)
            elif self._check_call_names(node.right, self.TRANS_FUNC):
                self.add_error(node.right)
        super(CheckForTransAdd, self).generic_visit(node)


def check_oslo_namespace_imports(logical_line, physical_line, filename):
    if pep8.noqa(physical_line):
        return
    if re.match(oslo_namespace_imports, logical_line):
        msg = ("M333: '%s' must be used instead of '%s'.") % (
            logical_line.replace('oslo.', 'oslo_'),
            logical_line)
        yield(0, msg)


def dict_constructor_with_list_copy(logical_line):
    msg = ("M336: Must use a dict comprehension instead of a dict constructor"
           " with a sequence of key-value pairs."
           )
    if dict_constructor_with_list_copy_re.match(logical_line):
        yield (0, msg)


def factory(register):
    register(validate_log_translations)
    register(check_explicit_underscore_import)
    register(no_translate_debug_logs)
    register(CheckForStrExc)
    register(CheckForTransAdd)
    register(check_oslo_namespace_imports)
    register(dict_constructor_with_list_copy)
