Name: python-cb-yara-connector
Version: 2.0
Release: 2
Summary: Carbon Black Yara Agent
License: MIT
Requires: redis

%description
Carbon Black Yara Agent - Scans binaries with configured yara rules

%build
pyinstaller %{_sourcedir}/cb-yara-connector.spec

%install
mkdir -p ${RPM_BUILD_ROOT}/var/log/cb/integrations/yaraconnector
mkdir -p ${RPM_BUILD_ROOT}/usr/share/cb/integrations/yaraconnector
mkdir -p ${RPM_BUILD_ROOT}/etc/cb/integrations/yaraconnector
mkdir -p ${RPM_BUILD_ROOT}/etc/init
cp yara.conf ${RPM_BUILD_ROOT}/etc/cb/integrations/yaraconnector/yaraconnector.conf.example
install -m 0755 init-scripts/yaraconnector.conf ${RPM_BUILD_ROOT}/etc/init/yaraconnector.conf
install -m 0755 dist/yaraconnector ${RPM_BUILD_ROOT}/usr/share/cb/integrations/yaraconnector/yaraconnector

%files -f MANIFEST