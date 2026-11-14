#!/bin/bash
# Rebuild targets, run the complete scenario matrix, and collect the
# deliverable artifacts into delivery/ (gitignored). Run from the repo root:
#   ./package_deliverables.sh
# Requires: network (cJSON clone), Docker, Python dependencies.
set -euo pipefail
cd "$(dirname "$0")"

if [ -x .venv/bin/python ]; then
    PYTHON=.venv/bin/python
else
    PYTHON=python3
fi

export PYTHONPATH=src

rm -rf delivery outputs
mkdir -p delivery/reports delivery/reproducers delivery/regression-suites delivery/configs

./targets/build_fixture_target.sh >/dev/null
./targets/build_cjson_target.sh >/dev/null

FAILED=0
run_collect() {
    local scenario="$1" expected="$2"
    local out="delivery/reports/$scenario"
    mkdir -p "$out"
    set +e
    "$PYTHON" -m patch_validator validate \
        --config "targets/configs/$scenario.yaml" \
        --output-json "$out/report.json" \
        --output-md "$out/SUMMARY.md" \
        > "$out/stdout.log" 2>&1
    local actual=$?
    set -e
    if [ "$actual" -eq "$expected" ]; then
        echo "$scenario: exit $actual (expected $expected)"
    else
        echo "FAIL $scenario: exit $actual (expected $expected)"
        FAILED=1
    fi
}

run_collect scenario-correct 0
run_collect scenario-incomplete 10
run_collect scenario-regression 20
run_collect scenario-no-bug 40
run_collect scenario-build-fail 30
run_collect scenario-cjson-correct 0
run_collect scenario-cjson-incomplete 10
run_collect scenario-cjson-regression 20

for target in fixture-target cjson-target; do
    for scenario_dir in outputs/"$target"/*/; do
        scenario=$(basename "$scenario_dir")
        mkdir -p "delivery/reproducers/$target/$scenario" \
                 "delivery/regression-suites/$target/$scenario"
        if [ -d "$scenario_dir/reproducers" ]; then
            cp -r "$scenario_dir/reproducers" "delivery/reproducers/$target/$scenario/"
        fi
        if [ -d ".regressions/$target/$scenario" ]; then
            cp -r ".regressions/$target/$scenario" "delivery/regression-suites/$target/$scenario/regression_suite"
        fi
    done
done

cp targets/configs/*.yaml delivery/configs/
cp targets/build_fixture_target.sh targets/build_cjson_target.sh delivery/configs/

mkdir -p delivery/targets
git -C targets/fixture_target bundle create "$(pwd)/delivery/targets/fixture_target.bundle" --all
git -C targets/cjson_target bundle create "$(pwd)/delivery/targets/cjson_target.bundle" --all
mapfile -t SANDBOX_IMAGES < <("$PYTHON" - <<'PY'
import json
from pathlib import Path
images = set()
for path in Path("delivery/reports").glob("*/report.json"):
    image = json.loads(path.read_text()).get("execution_settings", {}).get("sandbox_image")
    if image:
        images.add(image)
for image in sorted(images):
    print(image)
PY
)
if [ "${#SANDBOX_IMAGES[@]}" -gt 0 ]; then
    docker save -o delivery/sandbox-images.tar "${SANDBOX_IMAGES[@]}"
fi

cat > delivery/MANIFEST.md <<'EOF'
# Delivery manifest

- `reports/<scenario>/report.json` + `SUMMARY.md` — generated from real scenario
  executions (fixture target: 5 scenarios; cJSON: 3 scenarios).
- `reproducers/<target>/<scenario>/reproducers/{base,patched}/<finding_id>/` —
  self-contained reproducer bundles (crashing input, minimized input, copied
  binary, metadata.json, reproduce.sh). The `metadata.json` files record the
  build workspace paths where the runs happened — those are provenance
  records, not requirements: every bundle replays standalone via its own
  `reproduce.sh` (run it from any directory).
- `regression-suites/<target>/<scenario>/` — promoted regression inputs and
  manifest.json. All `input_path` entries in the manifests are relative to
  the suite's `auto_generated/` directory, so the suites relocate cleanly.
- `configs/` — the scenario configurations used, plus the target builders.
- `targets/*.bundle` — immutable git bundles of both target repositories with
  every revision the configs reference. Restore them with:
  `git clone delivery/targets/fixture_target.bundle targets/fixture_target`
  (and the same for `cjson_target.bundle`).
- `sandbox-images.tar` — recorded Docker runtime images; restore with
  `docker load -i delivery/sandbox-images.tar` before replaying a bundle on
  another machine. Each production `reproduce.sh` runs the recorded image
  with its effective environment, resource limits, and no network.
- Reproduce everything: `./run_all_scenarios.sh` from the repository root
  (see docs/09 and docs/10 for setup).
EOF

echo "deliverables collected in delivery/"
[ "$FAILED" -ne 0 ] && echo "WARNING: one or more scenarios failed" && exit 1
exit 0
