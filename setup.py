# setup.py

from setuptools import setup

__version__ = '0.1.0'

with open('README.md','r',encoding='utf8') as f:
  long_description = f.read()

install_requires = []
tests_requires   = []
extras_requires  = {}

if __name__ == '__main__': 
  setup( name='nbcc',
    classifiers=[
      'Development Status :: 4 - Beta',
      'Environment :: Console',
      'Intended Audience :: Developers',
      'License :: Free To Use But Restricted',
      'Operating System :: OS Independent',
      'Programming Language :: Python :: 3',
      'Topic :: Software Development',
      'Topic :: Software Development :: Debuggers',
      'Topic :: Software Development :: Libraries',
      'Topic :: Utilities' ],
    packages=['nbcc'],
    version=__version__,
    install_requires=install_requires,
    tests_require=tests_requires,
    extras_require=extras_requires,
    include_package_data=True,
    description='NBC Command line tools',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Red Brick Inc.',
    keywords='python NBC library SDK CLI tool DAPP development',
    url='https://github.com/fn-share/nbcc',
    scripts=['tools/nbcc'],
  )
