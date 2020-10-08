%define name python-cb-yara-connector
%define version 2.1.1
%define bare_version 2.1.1
%define release 1

%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%define _build_id_links none

%define build_timestamp %(date +%%y%%m%%d.%%H%%m%%S)

# If release_pkg is defined and has the value of 1, use a plain version string;
# otherwise, use the version string with a timestamp appended.
#
# if not otherwise defined (we do so on the rpmbuild command-line), release_pkg
# defaults to 0.
#
# see https://backreference.org/2011/09/17/some-tips-on-rpm-conditional-macros/
%if 0%{?release_pkg:1}
%if "%{release_pkg}" == "1"
%define decorated_version %{bare_version}
%else
%define decorated_version %{bare_version}.%{build_timestamp}
%endif
%endif

Summary: VMware Carbon Black EDR Yara Agent
Name: %{name}
Version: %{decorated_version}
Release: %{release}%{?dist}
License: MIT
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: VMware Carbon Black
Url: http://www.carbonblack.com/

%description
VMware Carbon Black EDR Yara Agent - Scans binaries with configured Yara rules

%build
cd %_sourcedir ; pyinstaller cb-yara-connector.spec

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
%else # EL7 and up
mkdir -p ${RPM_BUILD_ROOT}/etc/systemd/system
install -m 0644 ${RPM_SOURCE_DIR}/cb-yara-connector.service ${RPM_BUILD_ROOT}/etc/systemd/system/cb-yara-connector.service
%endif

cp ${RPM_SOURCE_DIR}/example-conf/yara.conf ${RPM_BUILD_ROOT}/etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example
install -m 0755 ${RPM_SOURCE_DIR}/dist/yaraconnector ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector/
install ${RPM_SOURCE_DIR}/yara-logo.png ${RPM_BUILD_ROOT}/usr/share/cb/integrations/cb-yara-connector/yara-logo.png
touch ${RPM_BUILD_ROOT}/var/log/cb/integrations/cb-yara-connector/yaraconnector.log
touch ${RPM_BUILD_ROOT}/tmp/yaraconnectorceleryworker

%files -f MANIFEST
%config /etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example

%preun
%if %{defined el6}
service cb-yara-connector stop
%else # EL7 and up
systemctl stop cb-yara-connector
%endif

