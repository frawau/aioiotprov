#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import setuptools
version = '0.0.2'

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(name='aioiotprov',
    packages=['aioiotprov','aioiotprov.plugins'],
    #packages=setuptools.find_packages(),
    version=version,
    author='François Wautier',
    author_email='francois@wautier.eu',
    description='Library/utility to help provision various IoT devices.',
    long_description=long_description,
    url='http://github.com/frawau/aioiotprov',
    keywords = ['IoT', 'provisioning', 'automation'],
    license='MIT',
    install_requires=[
    "aiohttp"
    ],
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5'
    ],
    zip_safe=False)
