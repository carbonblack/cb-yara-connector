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
mkdir -p /var/log/cb/integrations/yaraconnector
mkdir -p /usr/share/cb/integrations/yaraconnector
mkdir -p /etc/cb/integrations/yaraconnector
cp yara.conf /etc/cb/integrations/yaraconnector/yaraconnector.conf.example
install -m 0755 init-scripts/yaraconnector.conf /etc/init/yaraconnector.conf
install -m 0755 dist/yaraconnector /usr/share/cb/integrations/yaraconnector/yaraconnector

%files -f MANIFEST

%config /etc/init/yaraconnector.conf
%config(noreplace) /etc/cb/integrations/yaraconnector/yaraconnector.conf