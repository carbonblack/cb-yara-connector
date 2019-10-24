################################################################################
# Exception Classes
################################################################################


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
    pass


class CbInvalidFeed(CbException):
    pass


class CbInvalidReport(CbException):
    pass
