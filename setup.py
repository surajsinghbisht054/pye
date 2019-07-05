#!/usr/bin/env python3

from distutils.core import setup

setup(name='raw_python',
      version='2018.12.04',
      description='Python Package For Raw Packets Programming',
      python_requires='>3.0',
      license='Apache-2.0',
      url='https://github.com/lightsing/raw_python',
      author='Lightsing',
      packages=['raw_python', 'raw_python.lib', 'raw_python.samples'],
      package_data = {
        '': ['README.md', '*.readme']
      }
     )
