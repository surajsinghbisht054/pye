#!/usr/bin/env python3

from distutils.core import setup

setup(name='raw_python',
      version='0.1',
      description='Python Package For Raw Packets Programming',
      license='Apache-2.0',
      url='https://github.com/hguandl/raw_python',
      author='hguandl',
      author_email='hguandl@gmail.com',
      packages=['raw_python', 'raw_python.lib', 'raw_python.samples'],
      package_data = {
        '': ['README.md', '*.readme']
      }
     )