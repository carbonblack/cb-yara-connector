SOURCEDIR = ~/rpmbuild/SOURCES
BUILDDIR = ~/pmbuild/BUILD

clean:
	rm -rf ${SOURCEDIR}
	rm -rf ${BUILDDIR}
	rm -rf dist
rpm:
	mkdir -p ${SOURCEDIR}
	mkdir -p ${BUILDDIR}
	mkdir -p ${SOURCEDIR}/src
	mkdir -p ${BUILDDIR}/src
	mkdir -p ${BUILDDIR}/init-scripts
	mkdir -p ${BUILDDIR}/example-conf
	cp yara-logo.png ${SOURCEDIR}/yara-logo.png
	cp -rp src/* ${SOURCEDIR}/src
	cp -rp src/* ${BUILDDIR}/src
	cp -rp init-scripts/* ${BUILDDIR}/init-scripts
	cp example-conf/yara.conf ${BUILDDIR}/example-conf/yara.conf
	cp MANIFEST ${BUILDDIR}
	cp cb-yara-connector.service ${BUILDDIR}
	cp cb-yara-connector.spec ${SOURCEDIR}/cb-yara-connector.spec
	rpmbuild -ba cb-yara-connector.rpm.spec
