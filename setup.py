#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

VERSION = '0.8'

setup(
    name = 'webauthn-practice',
    packages = ['webauthn-practice'],
    include_package_data = True,
    version = VERSION,
    description = 'A Testing Platform for WebAuthn Authenticator and Brawser.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author = 'Seiji Nakaya / LOOSEDAYS',
    author_email = 'snakaya@loosedays.jp',
    url = 'https://github.com/snakaya/WebAuthn-practice',
    download_url = 'https://github.com/snakaya/WebAuthn-practice/archive/'
                   '{}.tar.gz'.format(VERSION),
    keywords = 'webauthn FIDO2 Flask Developing Tool',
    license='BSD',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Programming Language :: Python'
    ],
    install_requires=[
        'Flask>=1.0.2',
        'Flask-SQLAlchemy>=2.1',
        'SQLAlchemy>=1.0.13',
        'cbor2>=4.0.1',
        'cryptography>=2.3.1',
        'pyOpenSSL>=18.0.0',
        'six>=1.11.0'
    ]
)
