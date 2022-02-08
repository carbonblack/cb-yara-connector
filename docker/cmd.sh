#!/bin/bash

set -e

SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl.py"
if [[ "$(cat /etc/redhat-release)" == *"release 8"* ]]; then
  SYSTEM_CTL_PATCH="https://${ARTIFACTORY_SERVER}/artifactory/cb/gdraheim/docker-systemctl-replacement/1.4.3424/systemctl3.py"
fi

echo "creating mock postgres..."
sudo -u cb /usr/bin/postgres -D /postgres -p 5002 -h 127.0.0.1 &
sleep 3
sudo -u cb createdb -p 5002 && echo 'createdb ok!'
sudo -u cb psql -p 5002 -c "CREATE TABLE storefiles(md5hash BYTEA NOT NULL PRIMARY KEY, timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, present_locally BOOLEAN DEFAULT true, node_id INTEGER DEFAULT 0) ;"
sudo -u cb psql -p 5002 -c "insert into storefiles(md5hash, node_id) values('\x45f48b1aacccd555bbc84c9df0ce2fa6', 0);"
sudo -u cb psql -p 5002 -c "insert into storefiles(md5hash, node_id) values('\x14018eb9e2f4488101719c4d29de2230', 1);"
mkdir -p /var/cb/data/modulestore/45F/48B/
echo "45F48B1AACCCD555BBC84C9DF0CE2FA6" >> filedata
zip 45F48B1AACCCD555BBC84C9DF0CE2FA6.zip filedata
mv 45F48B1AACCCD555BBC84C9DF0CE2FA6.zip /var/cb/data/modulestore/45F/48B/45F48B1AACCCD555BBC84C9DF0CE2FA6.zip

echo 'mock postgres creation complete -- starting redis'
sudo systemctl start redis && echo 'redis started ok'

echo 'Starting smoke test server...'
cd $2 ; FLASK_APP=smoke_test_server.py python3.8 -m flask run --cert=adhoc &

echo Running connector...

cp $2/yaraconnector.conf /etc/cb/integrations/cb-yara-connector/
mkdir -p /etc/cb/integrations/cb-yara-connector/yara_rules
cp $2/smoketest*.yar /etc/cb/integrations/cb-yara-connector/yara_rules

/tmp/entrypoint.sh &
sleep 5
systemctl stop cb-yara-connector

count=$(grep -c "Matched yara rules: smoketest" /var/cb/data/cb-yara-connector/feed.json)
echo "count is $count"
if [ "$count" = "4" ]
then
  echo "Yara connector working ok!"
else
  echo "Yara connector not working ok!"
  exit 1
fi

log_line_count=$(wc -l /var/log/cb/integrations/cb-yara-connector/yaraconnector.log)
echo "Log line count is $log_line_count"
