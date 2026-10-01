#!/usr/bin/env python3
"""Build CarrierSIM without Python for the current OS: PyInstaller onedir + user files next to it.

Usage: build-standalone.py TAG DIST. Run with the Python that has requirements.txt and PyInstaller.
"""
import importlib.metadata
import pathlib
import platform
import shutil
import subprocess
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
# Next to the executable, not inside it: the user edits bundle.yaml, carrier.py verifies assets.zip.
SIDE_FILES = ('README.txt', 'README.md', 'bundle.yaml', 'assets.zip', 'LICENSE-AirLift.txt', 'LICENSE-AirCard.txt')


def target():
    machine = platform.machine().lower()
    if sys.platform == 'darwin':
        return 'macOS-' + ('arm64' if machine == 'arm64' else 'x86_64')
    if sys.platform == 'win32' and machine in ('amd64', 'x86_64'):
        return 'Windows-x64'
    raise SystemExit(f'Unsupported build platform: {sys.platform} {machine}')


def installed(name):
    try:
        importlib.metadata.version(name)
        return True
    except importlib.metadata.PackageNotFoundError:
        return False


def main(tag, dist):
    build = ROOT / 'build'
    shutil.rmtree(build, ignore_errors=True)
    subprocess.run([sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--console',
                    # Unbuffered like the script's "python -u", so output survives pipes and crashes;
                    # UTF-8 mode, or Russian text fails on a Windows pipe with a cp1252 locale.
                    '--python-option', 'u', '--python-option', 'X utf8',
                    '--name', 'CarrierSIM', '--collect-all', 'pymobiledevice3',
                    # carrier.py reports these versions in its diagnostics block; pylzss and lzfse
                    # are optional (placeholders on Python 3.13+, absent on some platforms).
                    *[a for p in ('cryptography', 'pyimg4', 'pylzss', 'lzfse') if installed(p) for a in ('--copy-metadata', p)],
                    '--workpath', str(build / 'work'), '--distpath', str(build / 'dist'),
                    '--specpath', str(build), str(ROOT / 'launch.py')], check=True, cwd=ROOT)
    app = build / 'dist' / 'CarrierSIM'
    for name in SIDE_FILES:
        shutil.copy2(ROOT / name, app / name)
    exe = app / ('CarrierSIM.exe' if sys.platform == 'win32' else 'CarrierSIM')
    # Smoke test of both roles: the launcher dispatch and carrier.py's own argument parser.
    # --check also imports the pymobiledevice3 services and runs the --_host helper; Windows runners have no iTunes.
    checks = [['--carrier', '--version'], ['--carrier', '--help']]
    if sys.platform == 'darwin': checks.append(['--carrier', '--check'])
    for args in checks:
        subprocess.run([str(exe), *args], check=True, cwd=app, stdout=subprocess.DEVNULL)
    dist = pathlib.Path(dist); dist.mkdir(parents=True, exist_ok=True)
    archive = dist / f'CarrierSIM-{tag}-{target()}.zip'
    archive.unlink(missing_ok=True)
    if sys.platform == 'darwin':
        # ditto keeps the framework symlinks and executable bits that zipfile would flatten.
        subprocess.run(['ditto', '-c', '-k', '--keepParent', str(app), str(archive)], check=True)
    else:
        with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as z:
            for path in sorted(app.rglob('*')):
                z.write(path, path.relative_to(app.parent))
    print(archive)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(*sys.argv[1:])
