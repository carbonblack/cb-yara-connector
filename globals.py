g_config = {}

g_cb_server_url = 'https://127.0.0.1'
g_cb_server_token = ''

broker_url = ''

g_yara_rules_dir = 'yara_rules'
output_file = 'yara_feed.json'

g_remote = False
g_yara_rule_map = {}
g_yara_rule_map_hash_list = list()

g_postgres_host = '127.0.0.1'
g_postgres_username = 'cb'
g_postgres_password = ''
g_postgres_port = 5002
g_postgres_db = 'cb'

MAX_HASHES = 8

g_num_binaries_not_available = 0
g_num_binaries_analyzed = 0

g_disable_rescan = False

g_num_days_binaries = 365
g_vacuum_seconds = -1
g_vacuum_script = 'vacuumscript.sh'
