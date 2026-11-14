#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

REPO=targets/fixture_target
CONFIGS=targets/configs
rm -rf "$REPO"
rm -f "$CONFIGS"/scenario-correct.yaml "$CONFIGS"/scenario-incomplete.yaml \
    "$CONFIGS"/scenario-regression.yaml "$CONFIGS"/scenario-no-bug.yaml \
    "$CONFIGS"/scenario-build-fail.yaml
mkdir -p "$REPO" "$CONFIGS"

cat > "$REPO/vuln.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <mode|payload>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "hang") == 0) {
        for (;;) {  }
    }
    if (strcmp(argv[1], "segv") == 0) {
        int *p = NULL;
        *p = 42;
        return 0;
    }
    
    char *buf = (char *)malloc(8);
    if (!buf) return 2;
    strcpy(buf, argv[1]);
    printf("ok:%s\n", buf);
    free(buf);
    return 0;
}
EOF

cat > "$REPO/correct.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <mode|payload>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "hang") == 0) {
        for (;;) { }
    }
    if (strcmp(argv[1], "segv") == 0) {
        fprintf(stderr, "segv mode disabled\n");
        return 0;
    }
    
    if (strlen(argv[1]) >= 8) {
        fprintf(stderr, "input too long\n");
        return 1;
    }
    char *buf = (char *)malloc(8);
    if (!buf) return 2;
    memcpy(buf, argv[1], strlen(argv[1]) + 1);
    printf("ok:%s\n", buf);
    free(buf);
    return 0;
}
EOF

cat > "$REPO/incomplete.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <mode|payload>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "hang") == 0) {
        for (;;) { }
    }
    
    if (strncmp(argv[1], "AAAA", 4) == 0 && strlen(argv[1]) >= 8) {
        fprintf(stderr, "input too long\n");
        return 1;
    }
    char *buf = (char *)malloc(8);
    if (!buf) return 2;
    strcpy(buf, argv[1]);
    printf("ok:%s\n", buf);
    free(buf);
    return 0;
}
EOF

cat > "$REPO/regression.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <mode|payload>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "hang") == 0) {
        for (;;) { }
    }
    
    if (strlen(argv[1]) >= 4) {
        fprintf(stderr, "input too long\n");
        return 1;
    }
    char *buf = (char *)malloc(8);
    if (!buf) return 2;
    memcpy(buf, argv[1], strlen(argv[1]) + 1);
    printf("ok:%s\n", buf);
    free(buf);
    return 0;
}
EOF

git -C "$REPO" init -q -b main
git -C "$REPO" config user.email "fixture@patchguard.local"
git -C "$REPO" config user.name "PatchGuard Fixture"
git -C "$REPO" add vuln.c
git -C "$REPO" commit -qm "base: vulnerable parser"
BASE_SHA=$(git -C "$REPO" rev-parse HEAD)

git -C "$REPO" checkout -q -b correct
cp "$REPO/correct.c" "$REPO/vuln.c"
git -C "$REPO" add vuln.c
git -C "$REPO" commit -qm "patch: bounds check (correct)"
CORRECT_SHA=$(git -C "$REPO" rev-parse HEAD)

git -C "$REPO" checkout -q "$BASE_SHA" -b incomplete
cp "$REPO/incomplete.c" "$REPO/vuln.c"
git -C "$REPO" add vuln.c
git -C "$REPO" commit -qm "patch: prefix-only check (incomplete)"
INCOMPLETE_SHA=$(git -C "$REPO" rev-parse HEAD)

git -C "$REPO" checkout -q "$BASE_SHA" -b regression
cp "$REPO/regression.c" "$REPO/vuln.c"
git -C "$REPO" add vuln.c
git -C "$REPO" commit -qm "patch: over-strict check (regression)"
REGRESSION_SHA=$(git -C "$REPO" rev-parse HEAD)

git -C "$REPO" checkout -q main
rm -f "$REPO/correct.c" "$REPO/incomplete.c" "$REPO/regression.c"

write_config() {
    local name="$1" base="$2" patched="$3" bypass_patched="$4"
    cat > "$CONFIGS/$name.yaml" <<EOF
target_name: fixture-target
repo_path: targets/fixture_target
base_ref: $base
patched_ref: $patched
build_cmd_release: "gcc -O2 -o vuln vuln.c"
build_cmd_sanitized: "gcc -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fsanitize=address,undefined -fno-omit-frame-pointer -g -O1 -o vuln vuln.c"
binary_rel_path: vuln
input_mode: args
argv_template: ["{input}"]
timeout_sec: 3.0
memory_mb: 256
cpus: 1.0
oracle_source: "fixture expectations designed by the team, specified independently of patched output"
work_dir: .work/fixture-target
output_dir: outputs/fixture-target/$name
regression_suite_dir: .regressions/fixture-target/$name
tests:
  - id: short-ok
    kind: functional
    input: "hi"
    expected_exit_code: 0
    is_valid_input: true
    stdout_kind: exact
    stdout_value: "ok:hi\n"
  - id: long-ok
    kind: functional
    input: "hello"
    expected_exit_code: 0
    is_valid_input: true
    stdout_kind: exact
    stdout_value: "ok:hello\n"
  - id: boundary-ok
    kind: boundary
    input: "1234567"
    expected_exit_code: 0
    is_valid_input: true
    stdout_kind: exact
    stdout_value: "ok:1234567\n"
  - id: poc-overflow
    kind: security
    input: "AAAAAAAAAAAA"
    expected_exit_code: 1
    is_valid_input: false
    stdout_kind: none
    stderr_pattern: "input too long"
    base_expect: {crash: true}
    patched_expect: {crash: false, exit_code: 1}
  - id: poc-bypass
    kind: security
    input: "BBBBBBBBBBBB"
    expected_exit_code: 1
    is_valid_input: false
    stdout_kind: none
    stderr_pattern: "input too long"
    base_expect: {crash: true}
    patched_expect: $bypass_patched
EOF
}

write_config scenario-correct "$BASE_SHA" "$CORRECT_SHA" "{crash: false, exit_code: 1}"
write_config scenario-incomplete "$BASE_SHA" "$INCOMPLETE_SHA" "{crash: true}"
write_config scenario-regression "$BASE_SHA" "$REGRESSION_SHA" "{crash: false, exit_code: 1}"
write_config scenario-no-bug "$CORRECT_SHA" "$CORRECT_SHA" "{crash: false, exit_code: 1}"
write_config scenario-build-fail "$BASE_SHA" "$CORRECT_SHA" "{crash: false, exit_code: 1}"

sed -i 's|gcc -O2 -o vuln vuln.c|gcc -O2 -o vuln nonexistent_source.c|' "$CONFIGS/scenario-build-fail.yaml"

echo "fixture target ready:"
echo "  base=$BASE_SHA correct=$CORRECT_SHA incomplete=$INCOMPLETE_SHA regression=$REGRESSION_SHA"
