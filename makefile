SOURCEDIR = ~/rpmbuild/SOURCES
BUILDDIR = ~/rpmbuild/BUILD
RPMDIR = ~/rpmbuild/RPMS
EL_VERSION := $(shell rpm -E %{rhel})

# non-release builds include a timestamp in the RPM name
# use "RELEASE=1 make rpm" for a release build, which will not use the timestamp
# RELEASE has a default value of 0
RELEASE ?= 0

clean:
	rm -rf ~/rpmbuild
	rm -rf dist
rpm:
	# Source DIR Setup
	mkdir -p ${SOURCEDIR}
	mkdir -p ${SOURCEDIR}/src
	mkdir -p ${SOURCEDIR}/example-conf

	cp yara-logo.png ${SOURCEDIR}/yara-logo.png
	cp -rp src/* ${SOURCEDIR}/src
	cp -rp  example-conf/yara.conf ${SOURCEDIR}/example-conf/yara.conf
	cp -rp cb-yara-connector ${SOURCEDIR}/cb-yara-connector
	cp cb-yara-connector.service ${SOURCEDIR}/cb-yara-connector.service
	cp cb-yara-connector.spec ${SOURCEDIR}/cb-yara-connector.spec
	cp -rp init-scripts/* ${SOURCEDIR}/init-scripts

	# Build DIR Setup
	mkdir -p ${BUILDDIR}
	cp -p MANIFEST${EL_VERSION} ${BUILDDIR}/MANIFEST

	$(info RELEASE is ${RELEASE})
	rpmbuild -v --define 'release_pkg ${RELEASE}' -ba cb-yara-connector.rpm.spec
