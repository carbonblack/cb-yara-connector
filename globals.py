# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

################################################################################
# This module contains global variables used by a single instance.
#
# A placeholder of "{YARA}" represents the location of this yara package
################################################################################

g_config = {}
g_output_file = ""

g_remote = False

# local info
g_cb_server_url = "https://127.0.0.1"
g_cb_server_token = ""

# remote info
g_broker_url = ""

g_yara_rules_dir = "{YARA}/local/yara_rules"
g_yara_rule_map = {}
g_yara_rule_map_hash_list = []

g_postgres_host = "127.0.0.1"
g_postgres_db = "cb"
g_postgres_username = "cb"
g_postgres_password = ""
g_postgres_port = 5002

g_max_hashes = 8
g_num_binaries_not_available = 0
g_num_binaries_analyzed = 0
g_disable_rescan = True
g_num_days_binaries = 365

# the vacuum interval, if 1 or greater, is the number of minutes between invocations of the
# configured vacuum script
g_vacuum_interval = -1
g_vacuum_script = "{YARA}/scripts/vacuumscript.sh"

g_feed_database_dir = "{YARA}/local/feed_db"
