# Installing Yara Agent (Centos/RHEL 6)

* Create directories


	mkdir -p /usr/share/cb/integrations/yara/yara_rules
	
* Download Yara Agent


	wget -O /usr/share/cb/integrations/yara/yara_agent <url to yara_agent>
	
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
	broker_url=redis://
	
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

	
* copy and modify the above config to `/etc/cb/integrations/yara/yara_agent.conf`

#### Run Yara Agent Manually

	./yara_agent --config-file=/etc/cb/integrations/yara/yara_agent.conf

#### Example Cron Entry

# Remote Worker Installation (Centos/RHEL 7)

* Install Python 3.6


	sudo yum install epel-release
	sudo yum install python36
	sudo yum install python36-devel
	
* Install Redis
	

	sudo yum install redis
	sudo systemctl start redis
	sudo systemctl enable redis
	
* Install Supervisord


	sudo yum install supervisor
	
* Install Yara Worker


	git clone https://github.com/carbonblack/cb-yara-connector.git
	cd cb-yara-connector
	git checkout yara_version2
	python3.6 -m venv venv
	source ./venv/bin/activate
	pip install -r requirements.txt
	mkdir yara_rules
	
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

	
	systemctl enable supervisord
	
* Restart Supervisor

	
	systemctl restart supervisord

# Centos 6 Build Instructions (Development)

## Install Dependencies

* zlib-devel
* openssl-devel
* sqlite-devel

## Install Python 3.6

	./configure --prefix=/usr/local --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib"
	make
	make altinstall

## Create VirtualEnv

	python3.6 -m venv venv-build
	source ./venv-build/bin/activate
	pip install -r requirements.txt

## Create Executable

	pyinstaller main.spec
