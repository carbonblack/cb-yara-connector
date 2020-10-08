# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

import time
from unittest import TestCase

from feed import CbInvalidReport, CbReport


# noinspection DuplicatedCode
class TestCbReport(TestCase):

    @staticmethod
    def core(**kwargs) -> dict:
        """
        Create default required fields.
        fields = {'iocs': {'md5': [binary.md5]},
                  'score': binary.score,
                  'timestamp': int(time.mktime(time.gmtime())),
                  'link': '',
                  'id': 'binary_{0}'.format(binary.md5),
                  'title': binary.last_success_msg,
                  'description': binary.last_success_msg
                  }
        :return:
        """
        iocs = {
            'md5': ["00000000001111111111222222222233", "11111111112222222222333333333344"]
        }

        data = {
            'id': "RepId1",
            'iocs': iocs,
            'link': "https://qa.carbonblack.com",
            'score': 22,
            'timestamp': int(time.time()),
            'title': "Unit test for report",
        }
        if len(kwargs) > 0:
            for key, value in kwargs.items():
                data[key] = value
        return data

    def test_fields_minimum(self):
        """
        Ensure minimum required fields.
        """
        data = self.core()
        rpt = CbReport(**data)
        rpt.validate()

    def test_fields_all(self):
        """
        Ensure all required fields.
        """
        data = self.core()
        data['description'] = "The Decription"
        data['tags'] = ["md5"]

        rpt = CbReport(**data)
        rpt.validate()

    def test_fields_all_required_only(self):
        """
        Ensure all required fields.
        """
        data = self.core()
        data['description'] = "The Decription"
        data['tags'] = ["md5"]

        rpt = CbReport(**data)
        rpt.validate()

        with self.assertRaises(CbInvalidReport) as err:
            rpt.validate(pedantic=True)
        assert "Report contains non-required key 'description'" in "{0}".format(err.exception.args[0])

    def test_fields_with_sha256(self):
        """
        Ensure sha256 ioc can be added.
        """
        iocs = {
            'sha256': ["0000000000111111111122222222223333333333444444444455555555556666"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"
        data['tags'] = ["sha256"]

        rpt = CbReport(**data)
        rpt.validate()

    def test_fields_with_ipv4(self):
        """
        Ensure ipv4 ioc can be added.
        """
        iocs = {
            'ipv4': ["12.34.56.78"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"
        data['tags'] = ["ipv4"]

        rpt = CbReport(**data)
        rpt.validate()

    def test_fields_with_query(self):
        """
        Ensure query ioc can be added.
        """
        iocs = {
            'query': [{
                'index_type': "events",
                'search_query': "cb.q.commandline=foo.txt"
            }]
        }
        data = self.core(iocs=iocs)
        data['description'] = "The Decription"
        data['tags'] = ["query"]

        rpt = CbReport(**data)
        rpt.validate()

    def test_fields_with_malformed_md5(self):
        """
        Ensure invalid md5 is caught.
        """
        iocs = {
            'md5': ["Bogus!!!Bogus!!!Bogus!!!Bogus!!!"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Malformed md5" in "{0}".format(err.exception.args[0])

    def test_fields_with_short_md5(self):
        """
        Ensure short md5 is caught.
        """
        iocs = {
            'md5': ["11111111112222222222"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Invalid md5 length" in "{0}".format(err.exception.args[0])

    def test_fields_with_long_md5(self):
        """
        Ensure long md5 is caught.
        """
        iocs = {
            'md5': ["1111111111222222222233333333334444444444"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Invalid md5 length" in "{0}".format(err.exception.args[0])

    def test_fields_with_malformed_sha256(self):
        """
        Ensure invalid sha256 is caught.
        """
        iocs = {
            'sha256': ["Bogus!!!Bogus!!!Bogus!!!Bogus!!!Bogus!!!Bogus!!!Bogus!!!Bogus!!!"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Malformed sha256" in "{0}".format(err.exception.args[0])

    def test_fields_with_short_sha256(self):
        """
        Ensure short sha256 is caught.
        """
        iocs = {
            'sha256': ["11111111112222222222"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Invalid sha256 length" in "{0}".format(err.exception.args[0])

    def test_fields_with_long_sha256(self):
        """
        Ensure long md5 is caught.
        """
        iocs = {
            'md5': ["1111111111222222222233333333334444444444555555555566666666667777777777"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Invalid md5 length" in "{0}".format(err.exception.args[0])

    def test_fields_with_malformed_ipv4(self):
        """
        Ensure invalid ipv4 is caught.
        """
        iocs = {
            'ipv4': ["Bogus"]
        }

        data = self.core(iocs=iocs)
        data['description'] = "The Decription"

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Malformed IPv4 addr" in "{0}".format(err.exception.args[0])

    def test_fields_with_query_missing_index_type(self):
        """
        Ensure query with missing index type is caught.
        """
        iocs = {
            'query': [{
                'search_query': "cb.q.commandline=foo.txt"
            }]
        }
        data = self.core(iocs=iocs)
        data['description'] = "The Decription"
        data['tags'] = ["query"]

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Query IOC section for report 'RepId1' missing index_type" in "{0}".format(err.exception.args[0])

    def test_fields_with_query_invalid_index_type(self):
        """
        Ensure query with bogus index type is caught.
        """
        iocs = {
            'query': [{
                'index_type': "BOGUS",
                'search_query': "cb.q.commandline=foo.txt"
            }]
        }
        data = self.core(iocs=iocs)
        data['description'] = "The Decription"
        data['tags'] = ["query"]

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Report IOCs section for 'query' contains invalid index_type: BOGUS" in "{0}".format(
            err.exception.args[0])

    def test_fields_with_query_missing_query(self):
        """
        Ensure query with missing query is caught.
        """
        iocs = {
            'query': [{
                'index_type': "events",
            }]
        }
        data = self.core(iocs=iocs)
        data['description'] = "The Decription"
        data['tags'] = ["query"]

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Query IOC for report RepId1 missing 'search_query'" in "{0}".format(err.exception.args[0])

    def test_fields_with_query_bogus_query(self):
        """
        Ensure query with missing query is caught.
        """
        iocs = {
            'query': [{
                'index_type': "events",
                'search_query': "BOGUS"
            }]
        }
        data = self.core(iocs=iocs)
        data['description'] = "The Decription"
        data['tags'] = ["query"]

        with self.assertRaises(CbInvalidReport) as err:
            rpt = CbReport(**data)
            rpt.validate()
        assert "Query IOC for report RepId1 missing q= on query" in "{0}".format(err.exception.args[0])
