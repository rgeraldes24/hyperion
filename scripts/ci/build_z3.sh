#!/usr/bin/env bash
# Build the pinned SMT solver for platforms without a prebuilt static package.
set -euo pipefail
REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
prefix="$REPO_ROOT/deps/z3"

if [[ ! -s $prefix/lib/libz3.a || ! -x $prefix/bin/z3 ]]; then
    work_dir=$(mktemp -d)
    trap 'rm -rf "$work_dir"' EXIT
    curl --fail --location --retry 3 \
        https://github.com/Z3Prover/z3/archive/refs/tags/z3-4.12.1.tar.gz \
        -o "$work_dir/z3.tar.gz"
    echo "a3735fabf00e1341adcc70394993c05fd3e2ae167a3e9bb46045e33084eb64a3  $work_dir/z3.tar.gz" | sha256sum -c -
    tar -xzf "$work_dir/z3.tar.gz" -C "$work_dir"
    cmake -S "$work_dir/z3-z3-4.12.1" -B "$work_dir/build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$prefix" \
        -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DZ3_BUILD_LIBZ3_SHARED=OFF -DZ3_BUILD_EXECUTABLE=ON \
        -DZ3_BUILD_TEST_EXECUTABLES=OFF -DZ3_ENABLE_EXAMPLE_TARGETS=OFF \
        -DZ3_INCLUDE_GIT_HASH=OFF -DZ3_INCLUDE_GIT_DESCRIBE=OFF
    cmake --build "$work_dir/build" --parallel "${BUILD_JOBS:-2}"
    cmake --install "$work_dir/build"
fi

"$prefix/bin/z3" --version
