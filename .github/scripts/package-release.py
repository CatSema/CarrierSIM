"""Package and verify the exact historical release tree, excluding .gitignore."""
import hashlib
import io
import pathlib
import subprocess
import sys
import zipfile

COMMITS = {
    'v1': '90a58df38cad7dee613793e6c699a30c4315f8ec',
    'v2': '4796103f698f76634f87611a0b4a432a27db3321',
    'v3': '6fcaeda44f3ddef06cdeca59f2ee53b075832847',
    'v4': '538414dc86a533d0d1c6b3a963233994679f64fa',
}


def git(*args):
    return subprocess.check_output(['git', *args])


def package(tag, destination):
    commit = COMMITS[tag]
    actual = git('rev-parse', f'refs/tags/{tag}^{{commit}}').decode().strip()
    if actual != commit:
        raise ValueError(f'{tag} points to {actual}, expected {commit}')
    expected = {}
    for entry in git('ls-tree', '-rz', '--full-tree', commit).split(b'\0'):
        if not entry:
            continue
        metadata, raw_name = entry.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        name = raw_name.decode('utf-8')
        if pathlib.PurePosixPath(name).name == '.gitignore':
            continue
        if kind != b'blob':
            raise ValueError(f'Unsupported tree entry: {name}')
        expected[name] = git('cat-file', 'blob', oid.decode())
    destination = pathlib.Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    archive_path = destination / f'CarrierSIM-{tag}-macOS-Windows.zip'
    raw = git('archive', '--format=zip', commit)
    with zipfile.ZipFile(io.BytesIO(raw)) as source:
        with zipfile.ZipFile(archive_path, 'w') as archive:
            archive.comment = source.comment
            for entry in source.infolist():
                if pathlib.PurePosixPath(entry.filename).name != '.gitignore':
                    archive.writestr(entry, source.read(entry))
    with zipfile.ZipFile(archive_path) as archive:
        actual_files = {
            name: archive.read(name)
            for name in archive.namelist() if not name.endswith('/')
        }
        if archive.testzip() is not None or actual_files != expected:
            raise ValueError('Archive does not match the Git tree byte-for-byte')
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    print(f'{tag}: {commit}; {len(expected)} files verified; SHA256 {digest}')
    return archive_path


if __name__ == '__main__':
    package(sys.argv[1], sys.argv[2])
