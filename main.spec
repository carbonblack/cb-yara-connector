# -*- mode: python -*-

block_cipher = None


a = Analysis(['main.py'],
             pathex=['.'],
             binaries=[],
             datas=[ (HOMEPATH + '/cbapi/response/models/*', 'cbapi/response/models/'),
                     (HOMEPATH + '/cbapi/protection/models/*', 'cbapi/protection/models/'),
                     (HOMEPATH + '/cbapi/defense/models/*', 'cbapi/defense/models/') ],
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
          name='yara_agent',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          runtime_tmpdir=None,
          console=True )
