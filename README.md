# Installing Yara Agent (Centos/RHEL 6)

The Yara agent must be installed on the same system as Cb Response.

* Create directories

	```
	mkdir -p /usr/share/cb/integrations/yara/yara_rules
	```
	
* Download Yara Agent

	```
	wget -O /usr/share/cb/integrations/yara/yara_agent https://github.com/carbonblack/cb-yara-connector/releases/download/2.0.1/yara_agent
	```
	
* Download Yara Logo

	```
	wget -O /usr/share/cb/integrations/yara/yara-logo.png https://github.com/carbonblack/cb-yara-connector/releases/download/2.0.1/yara-logo.png
	```
	
* Create Yara Agent Config File


#### Sample Yara Agent Config

	[general]

	;
	; either run a single worker locally or remotely
	; valid types are 'local' or 'remote'
	;
	worker_type=local
	
	;
	; ONLY for worker_type of remote
	; IP Address of workers if worker_type is remote
	;
	;broker_url=redis://
	
	;
	; path to directory containing yara rules
	;
	yara_rules_dir=yara_rules
	
	;
	; Cb Response postgres Database settings
	;
	postgres_host=
	postgres_username=
	postgres_password=
	postgres_db=
	postgres_port=
	
	;
	; ONLY for worker_type of local
	; Cb Response Server settings for scanning locally.
	; For remote scanning please set these parameters in the yara worker config file
	; Default: https://127.0.0.1
	;
	cb_server_url=
	cb_server_token=
	
	;
	; nice value used for this script
	;
	niceness=1
	
	;
	; Number of hashes to send to the workers concurrently.  Defaults to 8.
	; Recommend setting to the number of workers on the remote system.
	;
	concurrent_hashes=8
	
	;
	; If you don't want binaries to be rescanned more than once, regardless of the rules used, set this to True
	; Default: False
	;
	disable_rescan=False
	
	;
	; The agent will pull binaries up to the configured number of days.  For exmaple, 365 will pull all binaries with
	; a timestamp within the last year
	; Default: 365
	;
	num_days_binaries=365

	
* copy and modify the above config to `/etc/cb/integrations/yara/yara_agent.conf`

#### Running Yara Agent Manually

	./yara_agent --config-file=/etc/cb/integrations/yara/yara_agent.conf

#### Example Cron Entry

# Remote Worker Installation (Centos/RHEL 7)

* Make sure openssl-devel is installed

	```
	sudo yum install openssl-devel
    ```

* Install Git and GCC

	```
	sudo yum install git
	sudo yum install gcc
	```

* Install Python 3.6

	```
	sudo yum install epel-release
	sudo yum install python36
	sudo yum install python36-devel
	```
	
* Install Redis
	
	```
	sudo yum install redis
	sudo systemctl start redis
	sudo systemctl enable redis
	```
	
	
* Install Supervisord

	```
	sudo yum install supervisor
	```
	
* Install Yara Worker

	```
	git clone https://github.com/carbonblack/cb-yara-connector.git
	cd cb-yara-connector
	git checkout yara_version2
	python3.6 -m venv venv
	source ./venv/bin/activate
	pip install -r requirements.txt
	deactivate
	mkdir yara_rules
	```
	
	
* Create Yara Worker Config File `yara_worker.conf`

#### Example Yara Worker Config File

	[general]

	;
	; Python Celery Broker Url. Set this full url string for Redis
	; Example: redis://<ip_address>
	;
	broker_url=redis://127.0.0.1
	
	;
	; Cb Response Server Configuration
	; Used for downloading binaries
	;
	cb_server_url=
	cb_server_token=
	
	;
	; Directory for temporary yara rules storage
	; WARNING: Put your yara rules with the yara agent.  This is just temporary storage.
	;
	yara_rules_dir=yara_rules
	
* Copy, modify and save to `yara_worker.conf`
	
#### Run Yara Worker Manually

	celery -A tasks worker --config-file=yara_worker.conf --concurrency=10 --loglevel=info
	
#### Example Supervisor Config

	[program:yara_workers]
	stdout_logfile=/var/log/yara_worker.log
	stderr_logfile=/var/log/yara_worker.log
	user=<username>
	directory=/home/<username>/cb-yara-connector
	command=/home/<username>/cb-yara-connector/venv/bin/celery -A tasks worker --config-file=yara_worker.conf --concurrency=10 --loglevel=info
	autostart=true
	autorestart=true
	
* Copy the above, modify and add to `/etc/supervisord.conf`

* Enabled Supervisor

	```
	systemctl enable supervisord
	```
	
* Restart Supervisor

	```
	systemctl restart supervisord
	```
# Development Notes	

## Yara Agent Build Instructions (Centos 6)

### Install Dependencies

* zlib-devel
* openssl-devel
* sqlite-devel

### Install Python 3.6

	
	./configure --prefix=/usr/local --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib"
	make
	make altinstall


### Create VirtualEnv


	python3.6 -m venv venv-build
	source ./venv-build/bin/activate
	pip install -r requirements.txt


### Create Executable


	pyinstaller main.spec
