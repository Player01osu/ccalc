#!/bin/sh

set -xe

CC="clang"
SRC="src/ccalc.c"
TARGET="target/ccalc"
CFLAGS="-Wall -Wextra -Wpedantic -std=c99 -ggdb -Wno-unused-parameter -Wno-unused-variable"

[ -d "./target" ] || mkdir -p "target"

${CC} -o ${TARGET} ${SRC} ${CFLAGS}

${TARGET}
