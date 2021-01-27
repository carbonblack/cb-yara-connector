ifndef RPMROOT
$(error RPMROOT not defined)
endif
$(info RPMROOT=$(RPMROOT))

SOURCEDIR = $(RPMROOT)/SOURCES
BUILDDIR = $(RPMROOT)/BUILD
RPMDIR = $(RPMROOT)/RPMS

$(info SOURCEDIR=$(SOURCEDIR))
$(info BUILDDIR=$(BUILDDIR))
$(info RPMDIR=$(RPMDIR))

clean:
	rm -rf $(RMPBUILD_DIR)
	rm -rf dist
rpm:
	# Source DIR Setup
	mkdir -p $(SOURCEDIR)
	mkdir -p $(SOURCEDIR)/src
	mkdir -p $(SOURCEDIR)/example-conf

	cp yara-logo.png $(SOURCEDIR)/yara-logo.png
	cp -rp src/* $(SOURCEDIR)/src
	cp -rp  example-conf/yara.conf $(SOURCEDIR)/example-conf/yara.conf
	cp -rp cb-yara-connector $(SOURCEDIR)/cb-yara-connector
	cp cb-yara-connector.service $(SOURCEDIR)/cb-yara-connector.service
	cp cb-yara-connector.spec $(SOURCEDIR)/cb-yara-connector.spec
	cp -rp init-scripts/* $(SOURCEDIR)/init-scripts

	# Build DIR Setup
	mkdir -p $(BUILDDIR)
	cp -p MANIFEST $(BUILDDIR)/MANIFEST

	rpmbuild -vv --define '_topdir $(RPMROOT)' -ba cb-yara-connector.rpm.spec
