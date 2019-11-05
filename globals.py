# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

################################################################################
# This module contains global variables used by a single instance.
################################################################################

g_config = {}
g_output_file = ""

g_remote = False

# local info
g_cb_server_url = "https://127.0.0.1"
g_cb_server_token = ""

# remote info
g_broker_url = ""

g_yara_rules_dir = "./yara_rules"
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

# the utility interval, if 1 or greater, is the number of minutes between invocations of the
# configured utility script
g_utility_interval = -1
g_utility_script = None

g_feed_database_dir = "./feed_db"
