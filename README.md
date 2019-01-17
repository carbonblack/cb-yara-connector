
install zlib
install openssl-devel
install sqlite-devel

# Running the agent

mkdir -p /usr/share/cb/integrations/yara/yara_rules`
wget <> /usr/share/cb/integrations/yara/yara_agent

## Sample Yara Agent Config

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
	
	;worker_ip=127.0.0.1
	
	;
	; ONLY for worker_type of local
	; Cb Response Server settings for scanning locally.
	; For remote scanning please set these parameters in the yara worker config file
	; Default: https://127.0.0.1
	;
	cb_server_url=
	cb_server_token=
	
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
	; nice value used for this script
	;
	niceness=1
	
* copy the above config to `/etc/cb/integrations/yara/yara_agent.conf`

# Example Cron Entry

##



# Centos 6 Build Instructions

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
	
# Centos 7 Build Instructions

## Install Python 3.6

## Create VirtualEnv

## Create Executable
