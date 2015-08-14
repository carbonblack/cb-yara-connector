__author__ = 'jgarman'

from setuptools import setup

setup(
    name='cb-yara-connector',
    version='1.0',
    packages=['cbopensource', 'cbopensource.connectors', 'cbopensource.connectors.yara'],
    url='https://github.com/carbonblack/cb-yara-connector',
    license='MIT',
    author='Bit9 + Carbon Black Developer Network',
    author_email='dev-support@bit9.com',
    description=
        'Connector for evaluating Yara signatures against the Carbon Black modulestore',
    install_requires=[
    'flask',],
    extras_require= {
    },
    entry_points = {
    },
    classifiers=[
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
         'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ],
    keywords='carbonblack bit9',

)
