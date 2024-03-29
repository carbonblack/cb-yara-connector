%define name python-cb-yara-connector
%define version 2.2.0
%define bare_version 2.2.0
%define release 4

%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%define _build_id_links none

%define venv_location $VIRTUAL_ENV_PATH

Summary: VMware Carbon Black EDR Yara Agent
Name: %{name}
Version: %{version}
Release: %{release}%{?dist}
Source0: %{name}-%{version}.tar.gz
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: VMware Carbon Black
Url: http://www.carbonblack.com/

%description
VMware Carbon Black EDR Yara Agent - Scans binaries with configured Yara rules

%prep
%setup -n %{name}-%{version}

%build
%{venv_location}/bin/pyinstaller %{_topdir}/SOURCES/cb-yara-connector.spec

%install
mkdir -p ${RPM_BUILD_ROOT}/var/log/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector
mkdir -p ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector/yara_rules
mkdir -p ${RPM_BUILD_ROOT}/tmp
mkdir -p ${RPM_BUILD_ROOT}/var/run/
mkdir -p ${RPM_BUILD_ROOT}/var/cb/data/cb-yara-connector/feed_db

%if %{defined el6}
mkdir -p ${RPM_BUILD_ROOT}/etc/init
mkdir -p ${RPM_BUILD_ROOT}/etc/init.d/
install -m 700 ${RPM_SOURCE_DIR}/cb-yara-connector ${RPM_BUILD_ROOT}/etc/init.d/cb-yara-connector
%else
mkdir -p ${RPM_BUILD_ROOT}/etc/systemd/system
install -m 0644 ${RPM_SOURCE_DIR}/cb-yara-connector.service ${RPM_BUILD_ROOT}/etc/systemd/system/cb-yara-connector.service
%endif

cp ${RPM_SOURCE_DIR}/example-conf/yara.conf ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example
install -m 0755 ${RPM_BUILD_DIR}/%{name}-%{version}/dist/yaraconnector ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector/
install ${RPM_SOURCE_DIR}/yara-logo.png ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector/yara-logo.png
touch ${RPM_BUILD_ROOT}/var/log/cb/integrations/cb-yara-connector/yaraconnector.log
touch ${RPM_BUILD_ROOT}/tmp/yaraconnectorceleryworker

%files
%defattr(-,root,root)
%config /etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example
%if %{defined el6}
/etc/init.d/cb-yara-connector
%else
/etc/systemd/system/cb-yara-connector.service
%endif
/tmp/yaraconnectorceleryworker
/usr/share/cb/integrations/cb-yara-connector/yara-logo.png
/usr/share/cb/integrations/cb-yara-connector/yaraconnector
/var/log/cb/integrations/cb-yara-connector/yaraconnector.log
%dir /etc/cb/integrations/cb-yara-connector/yara_rules

%preun
%if %{defined el6}
service cb-yara-connector stop
%else
systemctl stop cb-yara-connector
%endif

