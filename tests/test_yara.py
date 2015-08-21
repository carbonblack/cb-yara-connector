__author__ = 'jgarman'

import unittest
from cbint.utils.detonation import DetonationDaemon, CbAPIProducerThread
from cbint.utils.detonation.binary_analysis import DeepAnalysisThread
from cbopensource.connectors.yara.bridge import YaraConnector, YaraProvider
import os
import sys
import tempfile
from time import sleep
import multiprocessing
import socket
import threading


sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.mock_server import get_mocked_server

test_dir = os.path.dirname(os.path.abspath(__file__))


class ServerNeverWokeUpError(Exception):
    pass


def sleep_till_available(conn_tuple):
    num_retries = 5
    while num_retries:
        s = socket.socket()
        try:
            s.connect(conn_tuple)
        except socket.error:
            num_retries -= 1
            sleep(.1)
        else:
            return

    raise ServerNeverWokeUpError(conn_tuple)


class YaraTest(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.mkdtemp()
        config_path = os.path.join(test_dir, "data", "daemon.conf")

        mydir = os.path.dirname(os.path.abspath(__file__))
        binaries_dir = os.path.join(mydir, 'data', 'binary_data')
        self.mock_server = get_mocked_server(binaries_dir)
        self.mock_server_thread = threading.Thread(target=self.mock_server.run, args=['127.0.0.1', 7982])
        self.mock_server_thread.daemon = True
        self.mock_server_thread.start()
        sleep_till_available(('127.0.0.1', 7982))

        self.daemon = YaraConnector('yara-test', configfile=config_path, work_directory=self.temp_directory,
                                    logfile=os.path.join(self.temp_directory, 'test.log'), debug=True)
        self.daemon.validate_config()

        self.daemon.initialize_queue()

    def test_yara(self):
        CbAPIProducerThread(self.daemon.work_queue, self.daemon.cb, self.daemon.name, rate_limiter=0,
                            stop_when_done=True).run()

        yara_provider = YaraProvider('yara-test', os.path.join(test_dir, 'data', 'yara_rules'))
        dirty_flag = threading.Event()
        t = DeepAnalysisThread(self.daemon.work_queue, self.daemon.cb, yara_provider, dirty_event=dirty_flag)
        t.start()

        unanalyzed = self.daemon.work_queue.number_unanalyzed()
        while unanalyzed:
            print unanalyzed
            sleep(.1)
            unanalyzed = self.daemon.work_queue.number_unanalyzed()

        t.stop()
        t.join()
