from distutils.core import setup
from distutils.core import Command
from distutils import dir_util
from distutils.spawn import spawn

from distutils.file_util import write_file
from distutils.util import change_root, convert_path

import os

class RpmDirs(object):
    _standard_dirs = ('SOURCES', 'SPECS', 'BUILD', 'BUILDROOT', 'RPMS', 'SRPMS')

    def __init__(self, root: str):
        self._root = root
        self._dirs = {_dir: os.path.join(self._root, _dir) for _dir in self._standard_dirs}

    @property
    def root(self):
        return self._root

    @property
    def sources(self):
        return self._dirs['SOURCES']

    @property
    def specs(self):
        return self._dirs['SPECS']

    @property
    def build(self):
        return self._dirs['BUILD']

    @property
    def buildroot(self):
        return self._dirs['BUILDROOT']

    @property
    def rpms(self):
        return self._dirs['RPMS']

    @property
    def srpms(self):
        return self._dirs['SRPMS']

    def create_dirs(self):
        for _dir in self._dirs.values():
            dir_util.mkpath(_dir)


class build_rpm(Command):
    description = 'creates an RPM distribution'

    user_options = [
        ('rpmbuild-dir=', 'r', 'RPM Build output directory')
    ]

    def initialize_options(self):
        self.rpmbuild_dir = None

    def finalize_options(self):
        self.rpm_dirs = RpmDirs(self.rpmbuild_dir)

    def run(self):
        self.rpm_dirs.create_dirs()

        sdist = self.reinitialize_command('sdist')
        self.run_command('sdist')
        source = sdist.get_archive_files()[0]
        self.copy_file(source, self.rpm_dirs.sources)
        spawn(['make', 'rpm', f'RPMROOT={self.rpmbuild_dir}'])


setup(
    name='python-cb-yara-connector',
    version='2.1.2',
    packages=['cbopensource', 'cbopensource.connectors', 'cbopensource.connectors.yara_connector'],
    package_dir={'': 'src'},
    url='https://github.com/carbonblack/cb-yara-connector',
    license='MIT',
    author='Carbon Black Developer Network',
    author_email='dev-support@carbonblack.com',
    description=
    'VMware Carbon Black EDR Yara Agent - Scans binaries with configured Yara rules',
    # data_files=data_files,
    classifiers=[
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.6',
    ],
    keywords='vmware carbonblack bit9',
    cmdclass={'build_rpm': build_rpm}
)
