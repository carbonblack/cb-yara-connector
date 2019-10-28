################################################################################
# This module contains global variables used by a single instance.
################################################################################

# noinspection PyUnusedName
g_config = {}
g_output_file = './yara_feed.json'

g_remote = False

# local info
g_cb_server_url = 'https://127.0.0.1'
g_cb_server_token = ''

# remote info
# noinspection PyUnusedName
g_broker_url = ''

g_yara_rules_dir = './yara_rules'
g_yara_rule_map = {}
g_yara_rule_map_hash_list = []

g_postgres_host = '127.0.0.1'
g_postgres_username = 'cb'
g_postgres_password = ''
g_postgres_port = 5002
g_postgres_db = 'cb'

g_max_hashes = 8

g_num_binaries_not_available = 0
g_num_binaries_analyzed = 0

g_disable_rescan = True

g_num_days_binaries = 365

g_vacuum_seconds = -1
g_vacuum_script = './scripts/vacuumscript.sh'

g_feed_database_dir = "./"
