# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

################################################################################
# This module contains global variables used by a single instance.
################################################################################

# used by the agent
g_config = {}
g_output_file = ""
g_yara_rule_map = {}
g_yara_rule_map_hash_list = []

# configuration
g_mode = "primary"

g_cb_server_url = ""
g_cb_server_token = ""
g_broker_url = ""

g_yara_rules_dir = "./yara_rules"

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

g_feed_database_dir = "./feed_db"

g_scanning_interval = 360

g_utility_interval = 0
g_utility_script = ""
g_utility_debug = False  # dev use only, reduces interval from minutes to seconds!

g_minion_network_timeout = 5

g_celery_worker_kwargs = None
