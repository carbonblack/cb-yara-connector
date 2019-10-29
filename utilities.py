# coding: utf-8
# Copyright © 2014-2019 VMware, Inc. All Rights Reserved.

################################################################################
# This file contains various package-wide utility functions
################################################################################

import os

__all__ = ["YARAHOME", "placehold"]

# self location for the package; remember to update this if this file is moved!
YARAHOME = os.path.dirname(__file__)


def placehold(source: str) -> str:
    """
    Locate any important string placeholders and substitute live values for them.
    :param source: source string to convert
    :return: converted string
    """
    source = source.replace("{YARA}", YARAHOME)
    return source
