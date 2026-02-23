# Carbon Black EDR YARA Connector

## Overview

[YARA](https://virustotal.github.io/yara/)

The connector reads YARA rules from a configured directory to efficiently scan binaries as they are seen by the EDR server.
The generated threat information is used to produce an intelligence feed for ingest by the EDR Server.

## Support

* View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
* Use the [Developer Community Forum](https://community.carbonblack.com/community/resources/developer-relations) to discuss issues and get answers from other API developers in the Carbon Black Community.
* Report bugs and change requests to [Carbon Black Support](http://carbonblack.com/resources/support/).

## Quickstart Guide

The cb-yara-connector can be installed on any 64-bit Linux machine running CentOS/RHEL 7/8.

### Installation

#### Phase 1: Generate an Access Token

Before installing the Carbon Black EDR YARA Connector, you must generate an access token
from the [Broadcom Support Portal](https://support.broadcom.com). This token is used to authenticate with
the Broadcom package repository. For detailed screenshots, refer to
[Broadcom Knowledge Article 421110](https://knowledge.broadcom.com/external/article/421110).

> **Note:** Access tokens are scoped to the products purchased by your organization and remain valid for the
> duration of the associated product contract. A single token can be generated per support Site ID and used
> to access all entitled products associated with that site.

1. Log in to the [Broadcom Support Portal](https://support.broadcom.com).
   If you do not have an account, create one at https://profile.broadcom.com/web/registration.
2. Navigate to **My Dashboard** > **My Downloads**.
3. Click the **Registry Tokens** button (top right).
4. Select your **Site ID** from the dropdown and click **Generate Token**.
5. Enter an optional description (e.g., `Carbon Black EDR YARA Connector`) and click **Submit**.
6. Click **Copy Token** to copy the generated token string. Save it securely -- you will need it during installation.

#### Phase 2: Install Carbon Black EDR YARA Connector (RPM)

To install and configure the cb-yara-connector, perform these steps as `root` on your target Linux system.

##### Download the Installer

1. Return to **My Downloads** in the Broadcom Support Portal.
2. Search for **Carbon Black EDR Connectors**.
3. Select **Carbon Black EDR YARA Connector**.
4. Select the desired version and download the `.zip` file (e.g., `Carbon_Black_EDR_Yara_2_2_0.zip`).
5. Transfer the downloaded file to your target Linux server.

##### Extract the Installer

6. Navigate to the directory containing the uploaded zip file and extract it:

   ```
   unzip Carbon_Black_EDR_Yara_2_2_0.zip
   cd Carbon_Black_EDR_Yara_2_2_0
   ```

##### Set Up the Package Repository

7. Run the included script to authorize the package repository using the access token generated in Phase 1:

   ```
   chmod +x generate_yara_repo.sh
   sudo ./generate_yara_repo.sh
   ```

8. When prompted, enter the following:
   - **User:** Your Broadcom Support Portal login email
   - **Access Token:** The access token you generated in Phase 1

   On success, you will see:
   ```
   Repository file created successfully at /etc/yum.repos.d/CarbonBlackYara.repo
   ```

9. Verify the repository file to confirm the GPG key paths are correct:

   ```
   cat /etc/yum.repos.d/CarbonBlackYara.repo
   ```

##### Install the RPM

10. Install the YARA Connector via YUM:

    ```
    yum install python-cb-yara-connector
    ```

### Configure the YARA Connector

The installation process creates a sample configuration file: `/etc/cb/integrations/cb-yara-connector/yaraconnector.conf.example`.  Copy
this sample template to `/etc/cb/integrations/cb-yara-connector/yaraconnector.conf`,
which is the filename and location that the connector expects. Users must edit this file to supply any missing information:

The daemon will attempt to load the PostgreSQL credentials from the EDR server's `cb.conf` file, 
if available, falling back to the PostgreSQL connection information in the primary's configuration file using the 
`postgres_xxxx` keys in the config. The REST API location and credentials are specified in the `cb_server_url` and 
`cb_server_token` keys, respectively. 

```ini
;
; EDR server settings, required for standalone mode
; For remote workers, the cb_server_url mus be that of the primary
;
cb_server_url=https://127.0.0.1
cb_server_token=<API TOKEN GOES HERE>
```

### Create your YARA rules

The YARA connector monitors the directory `/etc/cb/integrations/cb-yara-connector/yara_rules` for files (`.yar`) each 
specifying one or more YARA rule. Your rules must have `meta` section with a 
`score = [1-10]` tag to appropriately score matching binaries.  This directory is 
configurable in your configuration file. C-style comments are supported.

#### Sample YARA Rule File
```
// Sample rule to match binaries over 100kb in size

rule matchover100kb {
	meta:
		score = 10
	condition:
		filesize > 100KB
}
```

### Starting and Stopping the Service

#### CentOS / Red Hat 7/8

| Action | Command |
| ------ | ------- |
| Start the service | `systemctl start cb-yara-connector` |
| Stop the service | `systemctl stop cb-yara-connector` |
| Display service status | `systemctl status -l cb-yara-connector` |
| Displaying verbose logs | `journalctl -u cb-yara-connector` |

### Command-line Options
```text
usage: yaraconnector [-h] --config-file CONFIG_FILE [--log-file LOG_FILE]
                     [--output-file OUTPUT_FILE] [--working-dir WORKING_DIR]
                     [--pid-file PID_FILE] [--daemon]
                     [--validate-yara-rules] [--debug]

Yara Agent for Yara Connector

optional arguments:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE
                        location of the config file
  --log-file LOG_FILE   file location for log output
  --output-file OUTPUT_FILE
                        file location for feed file
  --working-dir WORKING_DIR
                        working directory
  --pid-file PID_FILE   pid file location - if not supplied, will not write a
                        pid file
  --daemon              run in daemon mode (run as a service)
  --validate-yara-rules
                        only validate the yara rules, then exit
  --debug               enabled debug level logging
```
#### --config-file
Provides the path of the configuration file to be used _**(REQUIRED)**_

#### --log-file
Provides the path of the YARA log file.  If not supplied, defaults to `local/yara_agent.log`
within the current YARA package.

#### --output-file
Provides the path containing the feed description file.  If not supplied, defaults to
`feed.json` in the same location as the configured `feed_database_dir` folder.

#### --validate-yara-rules
If supplied, YARA rules will be validated and then the service will exit

### Distributed Operations
The Yara integration for EDR supports a distributed mode of operation where a primary instance queues binaries 
to be scanned by a set of yara rules on a remote minion instance. 

The primary instance must be installed on an EDR primary node, and configured to access the EDR modulestore (postgres).
The minion instance must be installed on another machine, and needs to be configured with the API credentials for EDR.
The primary and minion communicate using the celery framework, which requires a celery-supported broker and 
results backend. 

* There are two operating modes to support the two roles: `mode=primary` and `mode=minion`. Both modes require a broker 
for Celery communications. Minion systems will need to change the mode to `minion`; 
* Remote minion systems will require the primary's URL for `cb_server_url` (local minions need no modification);
 they also require  the token of a global admin user for `cb_server_token`. 
* Remote minions will require the URL of the desired celery broker & results backend

The primary service must be installed on the same system as Carbon Black EDR, while minions are usually installed on other systems (but 
can also be on the primary system, if so desired). The YARA connector itself uses [Celery](http://www.celeryproject.org/) 
to distribute work to and remote (or local) minions - you will need to install and configure a 
[broker](https://docs.celeryproject.org/en/latest/getting-started/brokers/) (e.g., [Redis](https://redis.io/)) that is 
accessible to both the primary and remote minion instance(s).

You must configure `broker=` which sets the broker and can optionally configure `results_backend=` for Celery. 
Set this appropriately as per the [Celery documentation](https://docs.celeryproject.org/en/latest/getting-started/brokers/).

```ini
;
; URL of the celery broker, typically the EDR local redis service
;
broker_url=redis://127.0.0.1
;
; the URL of the desired results backend, either redis again or another supported backend
;
results_backend=redis://
```

## Development Notes

### YARA Agent Build Instructions

The dockerfile in the top-level of the repo contains a CentOS 7 environment for running, building, and testing 
the connector. 

The provided script `docker-build-rpm.sh` will use docker to build the project, and place the RPM(s) in `${PWD}/RPMS`. 

---

### Dev install

Use Git to retrieve the project, create a new virtual environment using Python 3.6+, and use pip to install the requirements:

```
git clone https://github.com/carbonblack/cb-yara-connector
pip3 install -r requirements.txt
```
