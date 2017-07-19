# Carbon Black - Yara Connector

[Yara](http://plusvic.github.io/yara/) is the linga franca of malware analysts. 
With a robust language to define byte strings and clean, well-designed interfaces, 
many IR and security operations shops keep the results of their analysis in a local
repository of yara rules.

However, monitoring activity across your network for matches to your yara rules is 
difficult.  If possible at all, it usually involves infrequent, time-consuming scans.  
Since Carbon Black collects all executed binaries and has a robust API, it is possible
to configure your Carbon Black server to act as a "Yara Monitor" and automatically trigger
notification for any binary executed across your network matching any of your Yara rules.

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-yara-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/yara/connector.conf.example` file to 
`/etc/cb/integrations/yara/connector.conf`. Edit this file and place your Carbon Black API key into the 
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.
Also, point the Yara connector to a directory of yara rule files by editing the `yara_rule_directory` variable. A set
of example rules are included in the `/usr/share/cb/integrations/yara/example_rules` directory.

To start the service, run `service cb-yara-connector start` as root. Any errors will be logged into `/var/log/cb/integrations/yara/yara.log`.

## Troubleshooting

If you suspect a problem, please first look at the Yara connector logs found here: `/var/log/cb/integrations/yara/yara.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:

1. Stop the service: `service cb-yara-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/yara/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-yara-connector start`

## Contacting Carbon Black Developer Relations Support

Web: https://developer.carbonblack.com
E-mail: dev-support@carbonblack.com

### Reporting Problems

When you contact Bit9 Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM) 
* For documentation issues, specify the version of the manual you are using. 
* Action causing the problem, error message returned, and event log output (as appropriate) 
* Problem severity
