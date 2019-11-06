#import distutils
#if distutils.distutils_path.endswith('__init__.py'):
#    distutils.distutils_path = os.path.dirname(distutils.distutils_path)

block_cipher = None


a = Analysis(['src/main.py'],
             pathex=['./src'],
             binaries=[],
             hiddenimports=['celery.fixups', 'celery.fixups.django', 'celery.loaders.app',
             				'celery.app.amqp', 'kombu.transport.redis', 'redis', 'celery.backends',
             				'celery.backends.redis', 'celery.app.events', 'celery.events',
             				'kombu.transport.pyamqp'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='yaraconnector',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          runtime_tmpdir=None,
          console=True )
