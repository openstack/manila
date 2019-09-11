#!/bin/bash

set -eu

usage() {
    echo "Usage: $0 [OPTION]..."
    echo "Run Manila's coding check(s)"
    echo ""
    echo " -Y, --pylint [<basecommit>] Run pylint check on the entire manila module or just files changed in basecommit (e.g. HEAD~1)"
    echo " -h, --help   Print this usage message"
    echo
    exit 0
}

process_options() {
    i=1
    while [ $i -le $# ]; do
        eval opt=\$$i
        case $opt in
            -h|--help) usage;;
            -Y|--pylint) pylint=1;;
            *) scriptargs="$scriptargs $opt"
        esac
        i=$((i+1))
    done
}

run_pylint() {

    local target="${scriptargs:-HEAD~1}"
    CODE_OKAY=0

    if [[ "$target" = *"all"* ]]; then
        files=$(find manila/ -type f -name "*.py" -and ! -path "manila/tests*")
        test_files=$(find manila/tests/ -type f -name "*.py")
    else
        files=$(git diff --name-only --diff-filter=ACMRU HEAD~1 ':!manila/tests/*' '*.py')
        test_files=$(git diff --name-only --diff-filter=ACMRU HEAD~1 'manila/tests/*.py')
    fi
    if [[ -z "${files}" || -z "${test_files}" ]]; then
        echo "No python changes in this commit, pylint check not required."
        exit 0
    fi
    if [[ -n "${files}" ]]; then
        echo "Running pylint against manila code modules:"
        printf "\t%s\n" "${files[@]}"
        pylint --rcfile=.pylintrc --output-format=colorized ${files} \
            -E -j 0 || CODE_OKAY=1
    fi
    if [[ -n "${test_files}" ]]; then
        echo "Running pylint against manila test modules:"
        printf "\t%s\n" "${test_files[@]}"
        pylint --rcfile=.pylintrc --output-format=colorized ${test_files} \
            -E -d "no-member,assignment-from-no-return,assignment-from-none" \
            -j 0 || CODE_OKAY=1
    fi
    exit $CODE_OKAY
}

scriptargs=
pylint=1

process_options $@

if [ $pylint -eq 1 ]; then
    run_pylint
    exit 0
fi
