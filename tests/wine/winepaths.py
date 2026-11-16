# Where the wine and wineserver programs are, shared by the Wine tests.
#
# Packaging differs between distributions and releases: Ubuntu 24.04 ships a
# wine64 command and /usr/bin/wineserver; newer Debian / Ubuntu releases only
# have /usr/bin/wine, with wineserver under /usr/lib/wine or the multiarch
# library folder. $WINE and $WINESERVER override the search.
import glob, os, shutil

def find_wine():
    return os.environ.get('WINE') or shutil.which('wine64') or shutil.which('wine') or '/usr/lib/wine/wine64'

def find_wineserver(wine):
    cands = [os.environ.get('WINESERVER'), shutil.which('wineserver'),
             os.path.join(os.path.dirname(wine), 'wineserver'),
             os.path.join(os.path.dirname(os.path.realpath(wine)), 'wineserver'),
             '/usr/lib/wine/wineserver', '/usr/lib/wine/wineserver64']
    cands += sorted(glob.glob('/usr/lib/*-linux-gnu/wine/wineserver*'))
    cands += sorted(glob.glob('/usr/lib/*-linux-gnu/wine/*/wineserver*'))
    for c in cands:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise SystemExit('wineserver not found (looked in: %s); set $WINESERVER' % ', '.join(c for c in cands if c))

WINE = find_wine()
WINESERVER = find_wineserver(WINE)
