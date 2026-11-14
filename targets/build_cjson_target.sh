#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

REPO=targets/cjson_target
CONFIGS=targets/configs
UPSTREAM=https://github.com/DaveGamble/cJSON.git
FIX_COMMIT=3ef4e4e730e5efd381be612df41e1ff3f5bb3c32

rm -rf "$REPO"
git clone -q "$UPSTREAM" "$REPO"
git -C "$REPO" config user.email "scenario@patchguard.local"
git -C "$REPO" config user.name "PatchGuard Scenario"
git -C "$REPO" fetch -q origin "$FIX_COMMIT"
BASE_COMMIT=$(git -C "$REPO" rev-parse "$FIX_COMMIT^")

write_driver() {
    cat > "$REPO/driver.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

int main(void) {
    char stack[4096];
    size_t length = fread(stack, 1, sizeof(stack) - 1, stdin);

    char *buffer = (char *)malloc(length);
    if (buffer == NULL) return 2;
    for (size_t i = 0; i < length; i++) buffer[i] = stack[i];
    cJSON *root = cJSON_ParseWithLength(buffer, length);
    free(buffer);
    if (root == NULL) {
        fprintf(stderr, "parse error\n");
        return 1;
    }
    char *printed = cJSON_PrintUnformatted(root);
    if (printed != NULL) {
        printf("%s\n", printed);
        free(printed);
    }
    cJSON_Delete(root);
    return 0;
}
EOF
}

make_scenario() {
    local branch="$1" base="$2" patch_mode="$3"
    git -C "$REPO" checkout -q -b "$branch" "$base"
    write_driver
    case "$patch_mode" in
        none)
            ;;
        incomplete)
            python3 - <<'PYEOF'
path = "targets/cjson_target/cJSON.c"
source = open(path).read()
decl_marker = "    cJSON *head = NULL; /* linked list head */"
assert source.count(decl_marker) == 1, "expected one head declaration"
source = source.replace(
    decl_marker,
    decl_marker + "\n    size_t loop_count = 0;",
    1,
)
fix = """        if (loop_count == 1)
        {
        if (cannot_access_at_index(input_buffer, 1))
        {
            goto fail;
        }
        }
        loop_count++;
"""
marker = "        /* parse the name of the child */"
assert source.count(marker) == 1, "expected one name-parse marker"
open(path, "w").write(source.replace(marker, fix + marker, 1))
PYEOF
            ;;
        regression)
            python3 - <<'PYEOF'
path = "targets/cjson_target/cJSON.c"
source = open(path).read()
fix = """        if (cannot_access_at_index(input_buffer, 1))
        {
            goto fail;
        }
"""
marker = "        /* parse the name of the child */"
assert source.count(marker) == 1, "expected one name-parse marker"
reject = """        if (buffer_at_offset(input_buffer)[0] == ',')
        {
            goto fail;
        }
"""
open(path, "w").write(source.replace(marker, fix + reject + marker, 1))
PYEOF
            ;;
    esac
    git -C "$REPO" add cJSON.c driver.c
    git -C "$REPO" commit -qm "scenario branch: $patch_mode patch"
}

git -C "$REPO" checkout -q --detach "$BASE_COMMIT"
git -C "$REPO" branch -q -D main 2>/dev/null || true
git -C "$REPO" branch -q -D master 2>/dev/null || true
make_scenario main "$BASE_COMMIT" none
git -C "$REPO" checkout -q -f main
BASE_SHA=$(git -C "$REPO" rev-parse HEAD)

make_scenario correct "$FIX_COMMIT" none
CORRECT_SHA=$(git -C "$REPO" rev-parse HEAD)

make_scenario incomplete "$BASE_SHA" incomplete
INCOMPLETE_SHA=$(git -C "$REPO" rev-parse HEAD)

make_scenario regression "$BASE_SHA" regression
REGRESSION_SHA=$(git -C "$REPO" rev-parse HEAD)

git -C "$REPO" checkout -q main

write_config() {
    local name="$1" base="$2" patched="$3" bypass_patched="$4"
    cat > "$CONFIGS/$name.yaml" <<EOF
target_name: cjson-target
repo_path: targets/cjson_target
base_ref: $base
patched_ref: $patched
build_cmd_release: "gcc -O2 -o cjson_test cJSON.c driver.c -lm"
build_cmd_sanitized: "gcc -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -o cjson_test cJSON.c driver.c -lm"
binary_rel_path: cjson_test
input_mode: stdin
timeout_sec: 5.0
memory_mb: 256
cpus: 1.0
oracle_source: "upstream cJSON behavior verified against the pinned commits; expected behavior is specified independently of patched output"
work_dir: .work/cjson-target
output_dir: outputs/cjson-target/$name
regression_suite_dir: .regressions/cjson-target/$name
tests:
  - id: valid-simple
    kind: functional
    input: '{"a":1}'
    expected_exit_code: 0
    is_valid_input: true
    stdout_kind: exact
    stdout_value: "{\"a\":1}\n"
  - id: valid-multi
    kind: functional
    input: '{"a":1,"b":[2,3]}'
    expected_exit_code: 0
    is_valid_input: true
    stdout_kind: exact
    stdout_value: "{\"a\":1,\"b\":[2,3]}\n"
  - id: boundary-empty
    kind: boundary
    input: '{}'
    expected_exit_code: 0
    is_valid_input: true
    stdout_kind: exact
    stdout_value: "{}\n"
  - id: poc-trailing-comma
    kind: security
    input: '{"1":1,'
    expected_exit_code: 1
    is_valid_input: false
    stdout_kind: none
    stderr_pattern: "parse error"
    base_expect: {crash: true}
    patched_expect: {crash: false, exit_code: 1}
  - id: poc-trailing-comma-multi
    kind: security
    input: '{"1":1,"2":2,'
    expected_exit_code: 1
    is_valid_input: false
    stdout_kind: none
    stderr_pattern: "parse error"
    base_expect: {crash: true}
    patched_expect: $bypass_patched
EOF
}

write_config scenario-cjson-correct "$BASE_SHA" "$CORRECT_SHA" "{crash: false, exit_code: 1}"
write_config scenario-cjson-incomplete "$BASE_SHA" "$INCOMPLETE_SHA" "{crash: true}"
write_config scenario-cjson-regression "$BASE_SHA" "$REGRESSION_SHA" "{crash: false, exit_code: 1}"

echo "cJSON target ready:"
echo "  base=$BASE_SHA correct=$CORRECT_SHA incomplete=$INCOMPLETE_SHA regression=$REGRESSION_SHA"
