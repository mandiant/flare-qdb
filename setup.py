# coding: utf-8
# Copyright (C) 2016 FireEye, Inc. All Rights Reserved.

import os
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name="flareqdb",
    version="1.0.0",
    author="Michael Bailey",
    author_email="michael.bailey@fireeye.com",
    description=("Query-oriented debugger"),
    license="Apache",
    keywords="native vivisect vtrace debug debugger",
    url="http://github.com/fireeye/flare-qdb/",
    packages=['flareqdb', 'flareqdb.scripts'],
    data_files=[
        ('flareqdb/scripts/32bit',
            [
                'flareqdb/scripts/32bit/dbghelp.dll',
                'flareqdb/scripts/32bit/symsrv.dll',
            ]
        ),
        ('flareqdb/scripts/64bit',
            [
                'flareqdb/scripts/64bit/dbghelp.dll',
                'flareqdb/scripts/64bit/symsrv.dll',
            ]
        )
    ],
    entry_points={
        'console_scripts': [
            'flareqdb = flareqdb.__main__:main',
            'dedosfuscator = flareqdb.scripts.deDOSfuscator:main'
        ]
    },
    long_description=read('README.md'),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Utilities",
        "License :: OSI Approved :: Apache License",
    ],
)
