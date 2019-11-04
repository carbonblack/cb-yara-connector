# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

import logging
import os
import sys
from multiprocessing import Process
from unittest import TestCase

from exceptions import SingleInstanceException
from singleton import SingleInstance

logger = logging.getLogger(__name__)


def f(flavor: str = None):
    tmp = logger.level
    logger.setLevel(logging.CRITICAL)  # we do not want to see the warning
    si = None
    try:
        si = SingleInstance(flavor_id=flavor)  # noqa
    except SingleInstanceException:
        sys.exit(1)
    finally:
        if si is not None:
            del si
        logger.setLevel(tmp)


class TestSingleInstance(TestCase):

    def test_01_unflavored(self):
        si = SingleInstance()
        logger.info("Lockfile: {0}".format(si.lockfile))
        self.assertTrue(os.path.exists(si.lockfile))

        lock = si.lockfile
        del si  # now the lock should be removed
        self.assertFalse(os.path.exists(lock))

    def test_02_flavored(self):
        si = SingleInstance(flavor_id="test-1")
        logger.info("Lockfile: {0}".format(si.lockfile))
        self.assertTrue(os.path.exists(si.lockfile))
        try:
            assert "test-1" in si.lockfile
        except AssertionError:
            del si
            raise

        lock = si.lockfile
        del si  # now the lock should be removed
        self.assertFalse(os.path.exists(lock))

    def test_03_specified(self):
        lockfile = '/tmp/foo.lock'
        si = SingleInstance(lockfile=lockfile)
        logger.info("Lockfile: {0}".format(si.lockfile))
        self.assertTrue(os.path.exists(lockfile))

        del si  # now the lock should be removed
        self.assertFalse(os.path.exists(lockfile))

    def test_04_as_process(self):
        p = Process(target=f, args=("as-process",))
        p.start()
        p.join()
        # the called function should succeed
        assert p.exitcode == 0, "%s != 0" % p.exitcode

    def test_05_as_process_multi_invoke(self):
        # get an instance running
        si = SingleInstance(flavor_id="test-05")

        p = Process(target=f, args=("test-05",))
        p.start()
        p.join()
        # the called function should fail because we already have another instance running
        assert p.exitcode != 0, "%s != 0 (2nd execution)" % p.exitcode

        # try a different flavor
        p = Process(target=f, args=("test-05a",))
        p.start()
        p.join()
        # the called function should fail because we already have another
        # instance running
        assert p.exitcode == 0, "%s != 0 (new flavor)" % p.exitcode

        del si
