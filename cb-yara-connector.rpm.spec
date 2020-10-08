%define name python-cb-yara-manager
%define version 2.1.3
%define release 1
%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
%define _build_id_links none

%define bare_version 2.1.3
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

Summary: VMware Carbon Black EDR Yara Manager
Name: %{name}
Version: %{decorated_version}
Release: %{release}%{?dist}
Source0: %{name}-%{bare_version}.tar.gz
License: Commercial
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: VMware Carbon Black
Url: http://www.carbonblack.com/

%description
UNKNOWN

%prep
%setup -n %{name}-%{bare_version}

%build
pyinstaller cb-yara-manager.spec

%install
python setup.py install_cb --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%posttrans
mkdir -p /var/log/cb/integrations/cb-yara-manager
chkconfig --add cb-yara-manager
chkconfig --level 345 cb-yara-manager on

# not auto-starting because conf needs to be updated
#/etc/init.d/cb-yara-connector start

%preun
/etc/init.d/cb-yara-manager stop

# only delete the chkconfig entry when we uninstall for the last time,
# not on upgrades
if [ "X$1" = "X0" ]
then
    chkconfig --del cb-yara-manager
fi


%files -f INSTALLED_FILES
%defattr(-,root,root)
