# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.

from unittest import TestCase

from cbopensource.connectors.yara_connector.feed import CbFeedInfo, CbIconError, CbInvalidFeed


class TestCbFeedInfo(TestCase):

    @staticmethod
    def core(**kwargs) -> dict:
        """
        Create default required fields.
        :return:
        """
        data = {
            'display_name': "Simple Test 123",
            'provider_url': "https://qa.carbonblack.com",
            'name': "simpletest123",
            'summary': "Unit test for feed info",
            'tech_data': "Unit test for feed info",
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
        fi = CbFeedInfo(**data)
        fi.validate()

    def test_fields_all(self):
        """
        Ensure all required fields.

        # TODO: update icon paths when we move source files
        """
        data = self.core()
        data['category'] = "Basic"
        data['icon'] = "../yara-logo.png"
        data['icon_small'] = "../yara-logo.png"
        data['version'] = 1

        fi = CbFeedInfo(**data)
        fi.validate()

    def test_missing_required_field(self):
        """
        Ensure minimum required fields.
        """
        data = self.core()
        del data['display_name']

        with self.assertRaises(CbInvalidFeed) as err:
            fi = CbFeedInfo(**data)
            fi.validate()
        assert "FeedInfo missing required field" in "{0}".format(err.exception.args[0])

    def test_extra_field(self):
        """
        Ensure no unexpected fields.
        """
        data = self.core()
        data['bogus'] = "foobar"

        with self.assertRaises(CbInvalidFeed) as err:
            fi = CbFeedInfo(**data)
            fi.validate()
        assert "FeedInfo includes extraneous key 'bogus'" in "{0}".format(err.exception.args[0])

    def test_field_wrong_type(self):
        """
        Ensure fields have expected type.
        """
        data = self.core()
        data['display_name'] = 5

        with self.assertRaises(CbInvalidFeed) as err:
            fi = CbFeedInfo(**data)
            fi.validate()
        assert "FeedInfo field 'display_name' must be of type" in "{0}".format(err.exception.args[0])

    def test_field_empty_string(self):
        """
        Ensure fields that are not allowed to be empty are caught.
        """
        data = self.core()
        data['display_name'] = ""

        with self.assertRaises(CbInvalidFeed) as err:
            fi = CbFeedInfo(**data)
            fi.validate()
        assert "The 'display_name' field must not be an empty string" in "{0}".format(err.exception.args[0])

    def test_bad_icon(self):
        """
        Ensure we trap bad icon data (only raises logger message)
        """
        data = self.core()

        fi = CbFeedInfo(**data)
        fi._data['icon'] = "BOGUS"
        fi.validate()

        data = self.core()

        fi = CbFeedInfo(**data)
        fi._data['icon_small'] = "BOGUS"
        fi.validate()

    def test_bad_icon_missing_path(self):
        """
        Ensure we trap bad icon data.
        """
        with self.assertRaises(CbIconError) as err:
            data = self.core(icon="nonesuch.png")
            CbFeedInfo(**data)
        assert "No such icon file at 'nonesuch.png'" in "{0}".format(err.exception.args[0])
