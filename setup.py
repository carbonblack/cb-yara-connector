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
        #
        # spawn(['rpmbuild', '-v', '-bb', '--define', f'_topdir {self.rpm_dirs.root}',
        #        f'{self.distribution.get_name()}.spec'])
        spawn(['make', 'rpm', f'RPMROOT={self.rpmbuild_dir}'])


# class install_cb(Command):
#     """This install_cb plugin will install all data files associated with the
#     tool as well as the pyinstaller-compiled single binary scripts so that
#     they can be packaged together in a binary RPM."""
#
#     description = "install binary distribution files"
#
#     user_options = [
#         ('install-dir=', 'd',
#          "base directory for installing data files "
#          "(default: installation base dir)"),
#         ('root=', None,
#          "install everything relative to this alternate root directory"),
#         ('force', 'f', "force installation (overwrite existing files)"),
#         ('record=', None,
#          "filename in which to record list of installed files"),
#     ]
#
#     boolean_options = ['force']
#
#     def initialize_options(self):
#         self.install_dir = None
#         self.outfiles = []
#         self.root = None
#         self.force = 0
#         self.data_files = self.distribution.data_files
#         self.warn_dir = 1
#         self.record = None
#
#     def finalize_options(self):
#         self.set_undefined_options('install',
#                                    ('install_data', 'install_dir'),
#                                    ('root', 'root'),
#                                    ('force', 'force'),
#                                    )
#
#     def run(self):
#         for f in self.data_files:
#             if isinstance(f, str):
#                 # don't copy files without path information
#                 pass
#             else:
#                 # it's a tuple with path to install to and a list of files
#                 dir = convert_path(f[0])
#                 if not os.path.isabs(dir):
#                     dir = os.path.join(self.install_dir, dir)
#                 elif self.root:
#                     dir = change_root(self.root, dir)
#                 self.mkpath(dir)
#
#                 if f[1] == []:
#                     # If there are no files listed, the user must be
#                     # trying to create an empty directory, so add the
#                     # directory to the list of output files.
#                     self.outfiles.append(dir)
#                 else:
#                     # Copy files, adding them to the list of output files.
#                     for data in f[1]:
#                         data = convert_path(data)
#                         (out, _) = self.copy_file(data, dir)
#                         self.outfiles.append(out)
#
#         for scriptname in scripts.keys():
#             pathname = scripts[scriptname]['dest']
#             dir = convert_path(pathname)
#             dir = os.path.dirname(dir)
#             dir = change_root(self.root, dir)
#             self.mkpath(dir)
#
#             data = os.path.join('dist', scriptname)
#             out = self.copy_tree(data, dir, preserve_mode=True)
#             self.outfiles.extend(out)
#
#         if self.record:
#             outputs = self.get_outputs()
#             if self.root:  # strip any package prefix
#                 root_len = len(self.root)
#                 for counter in range(len(outputs)):
#                     outputs[counter] = outputs[counter][root_len:]
#             self.execute(write_file,
#                          (self.record, outputs),
#                          "writing list of installed files to '%s'" %
#                          self.record)
#
#     def get_inputs(self):
#         return self.data_files or []
#
#     def get_outputs(self):
#         return self.outfiles


# # noinspection PySameParameterValue
# def get_data_files(rootdir):
#     # automatically build list of (dir, [file1, file2, ...],)
#     # for all files under src/root/ (or provided rootdir)
#     results = []
#     for root, dirs, files in os.walk(rootdir):
#         if len(files) > 0:
#             dirname = os.path.relpath(root, rootdir)
#             flist = [os.path.join(root, f) for f in files]
#             results.append(("/%s" % dirname, flist))
#
#     return results
#
#
# data_files = get_data_files("root")
# data_files.append('cb-taxii-connector.spec')
# data_files.append('scripts/cb-taxii-connector')
# scripts = {
#     'cb-taxii-connector': {
#         'spec': 'cb-taxii-connector.spec',
#         'dest': '/usr/share/cb/integrations/cbtaxii/bin/'
#     }
# }

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
    # cmdclass={'install_cb': install_cb, 'build_rpm': build_rpm}
    cmdclass={'build_rpm': build_rpm}
)
