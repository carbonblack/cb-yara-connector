FROM artifactory-pub.bit9.local:5000/cb/connector_env_base:centos7-1.4.0
ADD python-cb-yara-connector-*.el7.x86_64.rpm /tmp
ADD entrypoint.sh /tmp
RUN chmod +x /tmp/entrypoint.sh && yum -y install /tmp/python-cb-yara-connector-*.el7.x86_64.rpm
CMD /tmp/entrypoint.sh
