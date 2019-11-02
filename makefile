SOURCEDIR = ~/rpmbuild/SOURCES
BUILDDIR = ~/rpmbuild/BUILD

clean:
        rm -rf ${SOURCEDIR}
        rm -rf ${BUILDDIR}
        rm -rf dist
rpm:
        mkdir -p ${SOURCEDIR}
        mkdir -p ${BUILDDIR}
        mkdir -p ${SOURCEDIR}/src
        mkdir -p ${BUILDDIR}/init-scripts
        cp -rp src/* ${SOURCEDIR}/src
        cp -rp init-scripts/* ${BUILDDIR}/init-scripts
        cp yara.conf ${BUILDDIR}
        cp MANIFEST ${BUILDDIR}
        cp cb-yara-connector.spec ${SOURCEDIR}/cb-yara-connector.spec
        ls ${SOURCEDIR}
        rpmbuild -ba cb-yara-connector.rpm.spec