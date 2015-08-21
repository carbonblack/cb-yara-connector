# -*- mode: python -*-
a = Analysis(['scripts/cb-yara-connector'],
             pathex=['/home/builduser/git/cb-yara-connector'],
             hiddenimports=['unicodedata'],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='cb-yara-connector',
          debug=False,
          strip=None,
          upx=True,
          console=True )