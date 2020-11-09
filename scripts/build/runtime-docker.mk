# Copyright 2020 The arhat.dev Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# native
runtime-docker:
	sh scripts/build/build.sh $@

# linux
runtime-docker.linux.x86:
	sh scripts/build/build.sh $@

runtime-docker.linux.amd64:
	sh scripts/build/build.sh $@

runtime-docker.linux.armv5:
	sh scripts/build/build.sh $@

runtime-docker.linux.armv6:
	sh scripts/build/build.sh $@

runtime-docker.linux.armv7:
	sh scripts/build/build.sh $@

runtime-docker.linux.arm64:
	sh scripts/build/build.sh $@

runtime-docker.linux.mips:
	sh scripts/build/build.sh $@

runtime-docker.linux.mipshf:
	sh scripts/build/build.sh $@

runtime-docker.linux.mipsle:
	sh scripts/build/build.sh $@

runtime-docker.linux.mipslehf:
	sh scripts/build/build.sh $@

runtime-docker.linux.mips64:
	sh scripts/build/build.sh $@

runtime-docker.linux.mips64hf:
	sh scripts/build/build.sh $@

runtime-docker.linux.mips64le:
	sh scripts/build/build.sh $@

runtime-docker.linux.mips64lehf:
	sh scripts/build/build.sh $@

runtime-docker.linux.ppc64:
	sh scripts/build/build.sh $@

runtime-docker.linux.ppc64le:
	sh scripts/build/build.sh $@

runtime-docker.linux.s390x:
	sh scripts/build/build.sh $@

runtime-docker.linux.riscv64:
	sh scripts/build/build.sh $@

runtime-docker.linux.all: \
	runtime-docker.linux.x86 \
	runtime-docker.linux.amd64 \
	runtime-docker.linux.armv5 \
	runtime-docker.linux.armv6 \
	runtime-docker.linux.armv7 \
	runtime-docker.linux.arm64 \
	runtime-docker.linux.mips \
	runtime-docker.linux.mipshf \
	runtime-docker.linux.mipsle \
	runtime-docker.linux.mipslehf \
	runtime-docker.linux.mips64 \
	runtime-docker.linux.mips64hf \
	runtime-docker.linux.mips64le \
	runtime-docker.linux.mips64lehf \
	runtime-docker.linux.ppc64 \
	runtime-docker.linux.ppc64le \
	runtime-docker.linux.s390x \
	runtime-docker.linux.riscv64

runtime-docker.darwin.amd64:
	sh scripts/build/build.sh $@

# # currently darwin/arm64 build will fail due to golang link error
# runtime-docker.darwin.arm64:
# 	sh scripts/build/build.sh $@

runtime-docker.darwin.all: \
	runtime-docker.darwin.amd64

runtime-docker.windows.x86:
	sh scripts/build/build.sh $@

runtime-docker.windows.amd64:
	sh scripts/build/build.sh $@

runtime-docker.windows.armv5:
	sh scripts/build/build.sh $@

runtime-docker.windows.armv6:
	sh scripts/build/build.sh $@

runtime-docker.windows.armv7:
	sh scripts/build/build.sh $@

# # currently no support for windows/arm64
# runtime-docker.windows.arm64:
# 	sh scripts/build/build.sh $@

# currently all 32bit build will fail due to moby/term int overflow
runtime-docker.windows.all: \
	runtime-docker.windows.amd64

# # android build requires android sdk
# runtime-docker.android.amd64:
# 	sh scripts/build/build.sh $@

# runtime-docker.android.x86:
# 	sh scripts/build/build.sh $@

# runtime-docker.android.armv5:
# 	sh scripts/build/build.sh $@

# runtime-docker.android.armv6:
# 	sh scripts/build/build.sh $@

# runtime-docker.android.armv7:
# 	sh scripts/build/build.sh $@

# runtime-docker.android.arm64:
# 	sh scripts/build/build.sh $@

# runtime-docker.android.all: \
# 	runtime-docker.android.amd64 \
# 	runtime-docker.android.arm64 \
# 	runtime-docker.android.x86 \
# 	runtime-docker.android.armv7 \
# 	runtime-docker.android.armv5 \
# 	runtime-docker.android.armv6

runtime-docker.freebsd.amd64:
	sh scripts/build/build.sh $@

runtime-docker.freebsd.x86:
	sh scripts/build/build.sh $@

runtime-docker.freebsd.armv5:
	sh scripts/build/build.sh $@

runtime-docker.freebsd.armv6:
	sh scripts/build/build.sh $@

runtime-docker.freebsd.armv7:
	sh scripts/build/build.sh $@

runtime-docker.freebsd.arm64:
	sh scripts/build/build.sh $@

runtime-docker.freebsd.all: \
	runtime-docker.freebsd.amd64 \
	runtime-docker.freebsd.arm64 \
	runtime-docker.freebsd.armv7 \
	runtime-docker.freebsd.x86 \
	runtime-docker.freebsd.armv5 \
	runtime-docker.freebsd.armv6

runtime-docker.netbsd.amd64:
	sh scripts/build/build.sh $@

runtime-docker.netbsd.x86:
	sh scripts/build/build.sh $@

runtime-docker.netbsd.armv5:
	sh scripts/build/build.sh $@

runtime-docker.netbsd.armv6:
	sh scripts/build/build.sh $@

runtime-docker.netbsd.armv7:
	sh scripts/build/build.sh $@

runtime-docker.netbsd.arm64:
	sh scripts/build/build.sh $@

runtime-docker.netbsd.all: \
	runtime-docker.netbsd.amd64 \
	runtime-docker.netbsd.arm64 \
	runtime-docker.netbsd.armv7 \
	runtime-docker.netbsd.x86 \
	runtime-docker.netbsd.armv5 \
	runtime-docker.netbsd.armv6

runtime-docker.openbsd.amd64:
	sh scripts/build/build.sh $@

runtime-docker.openbsd.x86:
	sh scripts/build/build.sh $@

runtime-docker.openbsd.armv5:
	sh scripts/build/build.sh $@

runtime-docker.openbsd.armv6:
	sh scripts/build/build.sh $@

runtime-docker.openbsd.armv7:
	sh scripts/build/build.sh $@

runtime-docker.openbsd.arm64:
	sh scripts/build/build.sh $@

runtime-docker.openbsd.all: \
	runtime-docker.openbsd.amd64 \
	runtime-docker.openbsd.arm64 \
	runtime-docker.openbsd.armv7 \
	runtime-docker.openbsd.x86 \
	runtime-docker.openbsd.armv5 \
	runtime-docker.openbsd.armv6

runtime-docker.solaris.amd64:
	sh scripts/build/build.sh $@
