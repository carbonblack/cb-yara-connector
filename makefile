clean:
	rm -rf ~/rpmbuild/SOURCES/*

rpm:
	cp -r src ~/rpmbuild/SOURCES 
	cp -r init-scripts ~/rpmbuild/SOURCES 
	cp main.spec ~/rpmbuild/SOURCES/main.spec
	rpmbuild -ba cb-yara-agent.rpm.spec
