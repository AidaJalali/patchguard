#!/bin/bash
set -uo pipefail
cd "$(dirname "$0")"

./targets/build_fixture_target.sh >/dev/null

FAILED=0
run_scenario() {
    local name="$1" expected="$2"
    local out_dir="/tmp/patchguard-scenarios/$name"
    mkdir -p "$out_dir"
    PYTHONPATH=src "${PYTHON_BIN:-$([ -x .venv/bin/python ] && printf .venv/bin/python || printf python3)}" -m patch_validator validate \
        --config "targets/configs/$name.yaml" \
        --output-json "$out_dir/report.json" \
        --output-md "$out_dir/SUMMARY.md" \
        > "$out_dir/stdout.log" 2>&1
    local actual=$?
    if [ "$actual" -eq "$expected" ]; then
        echo "PASS $name: exit $actual (expected $expected)"
    else
        echo "FAIL $name: exit $actual (expected $expected)"
        tail -5 "$out_dir/stdout.log" | sed 's/^/    /'
        FAILED=1
    fi
}

run_scenario scenario-correct 0
run_scenario scenario-incomplete 10
run_scenario scenario-regression 20
run_scenario scenario-no-bug 40
run_scenario scenario-build-fail 30

if [ "${RUN_CJSON:-1}" = "1" ]; then
    if ./targets/build_cjson_target.sh >/dev/null 2>&1; then
        run_scenario scenario-cjson-correct 0
        run_scenario scenario-cjson-incomplete 10
        run_scenario scenario-cjson-regression 20
    else
        echo "FAIL: cJSON target setup failed (network?) — the open-source target scenarios are required"
        FAILED=1
    fi
else
    echo "SKIP: cJSON scenarios (RUN_CJSON=0)"
fi

if [ "$FAILED" -ne 0 ]; then
    echo "scenario matrix FAILED"
    exit 1
fi
echo "scenario matrix passed"
