#!/usr/bin/env python

from distutils.core import setup

setup(name="pyDes",
      version="2.0.1",
      description="Pure python implementation of DES and TRIPLE DES encryption algorithm",
      author="Todd Whiteman",
      author_email="twhitema@gmail.com",
      license='MIT',
      url="http://twhiteman.netfirms.com/des.html",
      classifiers=[
        'Development Status :: 6 - Mature'
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security :: Cryptography',
      ],
      platforms=["All"],
      keywords=["DES", "TRIPLE-DES", "ENCRYPTION", "ALGORITHM", "SECURITY"],
      py_modules=["pyDes"]
)
