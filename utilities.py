################################################################################
# This file contains various package-wide utility functions
################################################################################

import os

__all__ = ["YARAHOME", "placehold"]

# self location for the package
YARAHOME = os.path.dirname(__file__)


def placehold(source: str) -> str:
    """
    Locate any important string placeholders and substitute live values for them.
    :param source: source string to convert
    :return: converted string
    """
    source = source.replace("{YARA}", YARAHOME)
    return source
