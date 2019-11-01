clean:
	rm -rf ~/rpmbuild/SOURCES/*

rpm:
	cp -r src ~/rpmbuild/SOURCES 
	cp -r init-scripts ~/rpmbuild/SOURCES 
	cp cb-yara-connector.spec ~/rpmbuild/SOURCES/cb-yara-connector.spec
	rpmbuild -ba cb-yara-connector.rpm.spec