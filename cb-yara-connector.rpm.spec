%define version 2.1.0
%define release 1

Name: python-cb-yara-connector
Version: %{version}
Release: %{release}%{?dist}
Summary: Carbon Black Yara Agent
License: MIT
BuildArch: x86_64
Vendor: Carbon Black
Url: http://www.carbonblack.com/

%description
Carbon Black Yara Agent - Scans binaries with configured yara rules

%build
cd %_sourcedir ; pyinstaller cb-yara-connector.spec

%install
mkdir -p ${RPM_BUILD_ROOT}/var/log/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector/yara_rules
mkdir -p ${RPM_BUILD_ROOT}/etc/init
mkdir -p ${RPM_BUILD_ROOT}/etc/init.d/
mkdir -p ${RPM_BUILD_ROOT}/etc/systemd/system
mkdir -p ${RPM_BUILD_ROOT}/tmp
mkdir -p ${RPM_BUILD_ROOT}/var/run/
mkdir -p ${RPM_BUILD_ROOT}/var/cb/data/cb-yara-connector/feed_db
cp ${RPM_SOURCE_DIR}/example-conf/yara.conf ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example
install -m 0644 ${RPM_SOURCE_DIR}/cb-yara-connector.service ${RPM_BUILD_ROOT}/etc/systemd/system/cb-yara-connector.service
install -m 700 ${RPM_SOURCE_DIR}/cb-yara-connector ${RPM_BUILD_ROOT}/etc/init.d/cb-yara-connector
install -m 0755 ${RPM_SOURCE_DIR}/dist/yaraconnector ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector/
install ${RPM_SOURCE_DIR}/yara-logo.png ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector/yara-logo.png
touch ${RPM_BUILD_ROOT}/var/log/cb/integrations/cb-yara-connector/yaraconnector.log
touch ${RPM_BUILD_ROOT}/tmp/yaraconnectorceleryworker

%files -f MANIFEST
%config /etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example
