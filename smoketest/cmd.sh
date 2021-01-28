#!/bin/bash

set -e

if [ -z "$1" ]; then
  echo Error: Missing rpm file location parameter.  Ex: ./run_smoketest.sh path/to/rpm
  exit 1
fi

RPM_FILE=$(find "$1" -name "*.rpm" -print -quit)

SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl.py"
if [[ "$(cat /etc/redhat-release)" == *"release 8"* ]]; then
  SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl3.py"
fi

echo Adding cb user
groupadd cb --gid 8300 && \
useradd --shell /sbin/nologin --gid cb --comment "Service account for VMware Carbon Black EDR" -M cb

echo Running smoke test on file: "$RPM_FILE"

yum install -y "$RPM_FILE"

echo Running connector...

cp /etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example /etc/cb/integrations/cb-yara-connector/yaraconnector.conf
mkdir -p /etc/cb/integrations/cb-yara-connector/yara_rules

#systemctl start cb-yara-connector
/usr/share/cb/integrations/cb-yara-connector/yaraconnector --config-file /etc/cb/integrations/cb-yara-connector/yaraconnector.conf

# Uncomment the following line to leave the container running.
# sleep 9999999999
