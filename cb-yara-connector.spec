from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules('encodings')

block_cipher = None
hiddenimports.extend(['encodings.cp437', 'encodings','billiard','billiard.heap','lockfile','mmap','pkg_resources.py2_warn','celery.app.control','celery.worker.strategy','celery.worker.consumer','celery.events.state','celery.worker.autoscale','celery.worker.components','celery.concurrency.prefork','celery.apps','celery.apps.worker','celery.app.log','celery.fixups', 'celery.fixups.django', 'celery.loaders.app','celery.app.amqp', 'kombu.transport.redis', 'redis', 'celery.backends','celery.backends.redis', 'celery.app.events', 'celery.events', 'kombu.transport.pyamqp'])


a = Analysis(['src/cb-yara-connector'],
             pathex=['./src'],
             binaries=[],
             hookspath=[],
             runtime_hooks=[],
             hiddenimports=hiddenimports,
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
