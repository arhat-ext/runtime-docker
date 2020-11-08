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

# build
image.build.runtime-docker.linux.x86:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.amd64:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.armv5:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.armv6:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.armv7:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.arm64:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.ppc64le:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.mips64le:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.s390x:
	sh scripts/image/build.sh $@

image.build.runtime-docker.linux.all: \
	image.build.runtime-docker.linux.amd64 \
	image.build.runtime-docker.linux.arm64 \
	image.build.runtime-docker.linux.armv7 \
	image.build.runtime-docker.linux.armv6 \
	image.build.runtime-docker.linux.armv5 \
	image.build.runtime-docker.linux.x86 \
	image.build.runtime-docker.linux.s390x \
	image.build.runtime-docker.linux.ppc64le \
	image.build.runtime-docker.linux.mips64le

image.build.runtime-docker.windows.amd64:
	sh scripts/image/build.sh $@

image.build.runtime-docker.windows.armv7:
	sh scripts/image/build.sh $@

image.build.runtime-docker.windows.all: \
	image.build.runtime-docker.windows.amd64 \
	image.build.runtime-docker.windows.armv7

# push
image.push.runtime-docker.linux.x86:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.amd64:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.armv5:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.armv6:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.armv7:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.arm64:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.ppc64le:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.mips64le:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.s390x:
	sh scripts/image/push.sh $@

image.push.runtime-docker.linux.all: \
	image.push.runtime-docker.linux.amd64 \
	image.push.runtime-docker.linux.arm64 \
	image.push.runtime-docker.linux.armv7 \
	image.push.runtime-docker.linux.armv6 \
	image.push.runtime-docker.linux.armv5 \
	image.push.runtime-docker.linux.x86 \
	image.push.runtime-docker.linux.s390x \
	image.push.runtime-docker.linux.ppc64le \
	image.push.runtime-docker.linux.mips64le

image.push.runtime-docker.windows.amd64:
	sh scripts/image/push.sh $@

image.push.runtime-docker.windows.armv7:
	sh scripts/image/push.sh $@

image.push.runtime-docker.windows.all: \
	image.push.runtime-docker.windows.amd64 \
	image.push.runtime-docker.windows.armv7
