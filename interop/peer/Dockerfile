# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# Reference IEC 61850 peers for the interop tests: libiec61850 v1.6.2.1
# (MZ Automation, GPLv3, github.com/mz-automation/libiec61850, commit
# 6e7a603c771d6124cd3cafea7ec38b7e0f2e7aaf) built from source with the
# SQLite amalgamation 3.46.1 for its log service, its stock server, GOOSE
# and SV examples, and gspeer.c of this directory linked against it. The
# SCL files of libiec61850's examples, demos and tools are copied to /scl
# for the SCL parsing test. The image is a test peer only; nothing of it is
# distributed with the Go modules.
#
#   docker build -t sigma-iec61850-interop:libiec61850-1.6.2.1-p1 .

FROM debian:bookworm-slim AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends gcc g++ libc6-dev make cmake git ca-certificates curl unzip \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v1.6.2.1 https://github.com/mz-automation/libiec61850 /src/libiec61850 \
 && test "$(git -C /src/libiec61850 rev-parse HEAD)" = 6e7a603c771d6124cd3cafea7ec38b7e0f2e7aaf
WORKDIR /src/libiec61850/third_party/sqlite
RUN curl -fsSL -o sqlite.zip https://www.sqlite.org/2024/sqlite-amalgamation-3460100.zip \
 && unzip -j sqlite.zip '*/sqlite3.c' '*/sqlite3.h' && rm sqlite.zip
WORKDIR /src/libiec61850
# The top-level CMakeLists sets SQLITE_INCLUDE_DIR with a typo (no space
# before the value), so the amalgamation's directory is passed by hand.
RUN cmake -S . -B /build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DBUILD_PYTHON_BINDINGS=OFF \
    -DCMAKE_C_FLAGS=-I/src/libiec61850/third_party/sqlite \
 && cmake --build /build -j4 \
 && cmake --install /build --prefix /usr/local
RUN mkdir -p /out/bin /scl \
 && for e in server_example_basic_io server_example_control server_example_logging server_example_files server_example_goose; do \
      cp /build/examples/$e/$e /out/bin/; done \
 && cp /build/examples/server_example_setting_groups/server_example_sg /out/bin/server_example_setting_groups \
 && cp /build/examples/server_example_complex_array/server_example_ca /out/bin/server_example_complex_array \
 && cp /build/examples/goose_publisher/goose_publisher_example /build/examples/goose_subscriber/goose_subscriber_example \
      /build/examples/sv_publisher/sv_publisher_example /build/examples/sv_subscriber/sv_subscriber_example /out/bin/ \
 && cp -r /src/libiec61850/examples/server_example_files/vmd-filestore /out/vmd-filestore \
 && find . \( -iname '*.icd' -o -iname '*.cid' -o -iname '*.scd' -o -iname '*.iid' -o -iname '*.ssd' \) -exec cp --parents {} /scl/ \;
COPY gspeer.c /peer/
RUN gcc -O2 -o /out/bin/gspeer /peer/gspeer.c -I/usr/local/include -I/usr/local/include/libiec61850 \
    -L/usr/local/lib -liec61850 -lpthread -lm

FROM debian:bookworm-slim
COPY --from=build /out/bin/ /usr/local/bin/
COPY --from=build /usr/local/lib/ /usr/local/lib/
COPY --from=build /out/vmd-filestore /work/vmd-filestore
COPY --from=build /scl /scl
RUN ldconfig
WORKDIR /work
