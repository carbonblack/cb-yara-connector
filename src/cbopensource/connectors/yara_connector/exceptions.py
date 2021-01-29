# coding: utf-8
# Copyright © 2014-2020 VMware, Inc. All Rights Reserved.


class CbException(Exception):
    """
    Root exception for this connector.
    """
    pass


class CbInvalidConfig(CbException):
    """
    Exception raised on an invalid configuration file.
    """
    pass


class CbIconError(CbException):
    """
    Exception raised if supplied icon is bad.
    """
    pass


class CbInvalidFeed(CbException):
    """
    Excepion raised if supplied Feed data is invalid.
    """
    pass


class CbInvalidReport(CbException):
    """
    Excepion raised if supplied Report data is invalid.
    """
    pass
