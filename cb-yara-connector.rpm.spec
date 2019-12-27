Name: python-cb-yara-connector
Version: 2.0
Release: 2
Summary: Carbon Black Yara Agent
License: MIT
Requires: redis

%description
Carbon Black Yara Agent - Scans binaries with configured yara rules

%build
cd %_sourcedir ; pyinstaller cb-yara-connector.spec

%install
mkdir -p ${RPM_BUILD_ROOT}/var/log/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/etc/init
cp example-conf/yara.conf ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example
install -m 0755 init-scripts/yaraconnector.conf ${RPM_BUILD_ROOT}/etc/init/yaraconnector.conf
install -m 0755 ${RPM_SOURCE_DIR}/dist/yaraconnector ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector/

%files -f MANIFEST
