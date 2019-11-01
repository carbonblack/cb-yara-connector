Name: yaraagent
Version: 2.0
Release: 2
Summary: Carbon Black Yara Agent
License: MIT
Requires: redis

%description
Carbon Black Yara Agent - Scans binaries with configured yara rules

%build
pyinstaller %{_sourcedir}/main.spec

%install
mkdir -p %{buildroot}%{_bindir}
install -m 755 dist/yara_agent %{buildroot}%{_bindir}/yaraagent
install -m 755 %{_sourcedir}/init-scripts/yara.conf /etc/init/yara.conf

%files
%/etc/init.d/yaraagent
%/etc/init/yara.conf