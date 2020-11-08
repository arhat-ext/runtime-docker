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

#
# linux
#
package.runtime-docker.deb.amd64:
	sh scripts/package/package.sh $@

package.runtime-docker.deb.armv6:
	sh scripts/package/package.sh $@

package.runtime-docker.deb.armv7:
	sh scripts/package/package.sh $@

package.runtime-docker.deb.arm64:
	sh scripts/package/package.sh $@

package.runtime-docker.deb.all: \
	package.runtime-docker.deb.amd64 \
	package.runtime-docker.deb.armv6 \
	package.runtime-docker.deb.armv7 \
	package.runtime-docker.deb.arm64

package.runtime-docker.rpm.amd64:
	sh scripts/package/package.sh $@

package.runtime-docker.rpm.armv7:
	sh scripts/package/package.sh $@

package.runtime-docker.rpm.arm64:
	sh scripts/package/package.sh $@

package.runtime-docker.rpm.all: \
	package.runtime-docker.rpm.amd64 \
	package.runtime-docker.rpm.armv7 \
	package.runtime-docker.rpm.arm64

package.runtime-docker.linux.all: \
	package.runtime-docker.deb.all \
	package.runtime-docker.rpm.all

#
# windows
#

package.runtime-docker.msi.amd64:
	sh scripts/package/package.sh $@

package.runtime-docker.msi.arm64:
	sh scripts/package/package.sh $@

package.runtime-docker.msi.all: \
	package.runtime-docker.msi.amd64 \
	package.runtime-docker.msi.arm64

package.runtime-docker.windows.all: \
	package.runtime-docker.msi.all

#
# darwin
#

package.runtime-docker.pkg.amd64:
	sh scripts/package/package.sh $@

package.runtime-docker.pkg.arm64:
	sh scripts/package/package.sh $@

package.runtime-docker.pkg.all: \
	package.runtime-docker.pkg.amd64 \
	package.runtime-docker.pkg.arm64

package.runtime-docker.darwin.all: \
	package.runtime-docker.pkg.all
