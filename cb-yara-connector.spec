# -*- mode: python -*-
a = Analysis(['./src/main.py'],
             pathex=['./src'],
             binaries=[],
             hiddenimports=['billiard','billiard.heap','lockfile','mmap','pkg_resources.py2_warn','celery.app.control',
                            'celery.worker.strategy','celery.worker.consumer','celery.events.state',
                            'celery.worker.autoscale','celery.worker.components','celery.concurrency.prefork',
                            'celery.apps','celery.apps.worker','celery.app.log','celery.fixups', 'celery.fixups.django',
                            'celery.loaders.app','celery.app.amqp', 'kombu.transport.redis', 'redis', 'celery.backends',
                            'celery.backends.redis', 'celery.app.events', 'celery.events', 'kombu.transport.pyamqp'],
             datas=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='cb-yara-connector',
          debug=False,
          strip=None,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='cb-yara-connector')
