"""Package verified host-staged Debian dependencies and pinned HAPI jars for GNS3."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


MAVEN = 'https://repo.maven.apache.org/maven2/'
JARS = {
    'ca/uhn/hapi/hapi-base/2.5.1/hapi-base-2.5.1.jar': '5bed2ae8b9332e1e05bf1172478faca8d6c9a7ecd8f8d34ae475395b0e98e4af',
    'ca/uhn/hapi/hapi-structures-v25/2.5.1/hapi-structures-v25-2.5.1.jar': 'f91fd907896fbf93718201730b5b12ddf5ebbe07bc29909d08eef5038f331818',
    'org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar': 'd3ef575e3e4979678dc01bf1dcce51021493b4d11fb7f1be8ad982877c16a1c0',
    'org/slf4j/slf4j-simple/1.7.36/slf4j-simple-1.7.36.jar': '2f39bed943d624dfa8f4102d0571283a10870b6aa36f197a8a506f147010c10f',
    'joda-time/joda-time/2.1/joda-time-2.1.jar': '5bce965a5e1dc1add255f1791a18521a7a5ecf36e436acb7ce2e5eda9d1a8e10',
}


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', type=Path, required=True, help='Debian archives downloaded by signed APT')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    packages = sorted(args.packages.glob('*.deb'))
    for prefix in ('dcmtk_', 'default-jdk-headless_', 'openjdk-17-jre-headless_'):
        if not any(p.name.startswith(prefix) for p in packages):
            raise ValueError(f'Missing {prefix} in the staged Debian package directory')
    with tempfile.TemporaryDirectory(dir=args.output.parent) as folder:
        jars = []
        for resource, expected in JARS.items():
            path = Path(folder) / resource.rsplit('/', 1)[1]
            subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location', '--max-time', '60',
                            '--max-filesize', str(16 * 1024 * 1024), MAVEN + resource, '--output', str(path)], check=True)
            if sha256(path) != expected:
                raise ValueError(f'Unexpected SHA-256 for {path.name}')
            jars.append(path)
        members = packages + jars
        with args.output.open('xb') as target, tarfile.open(fileobj=target, mode='w') as archive:
            for path in members:
                archive.add(path, arcname=path.name, recursive=False)
        manifest = {'archive_sha256': sha256(args.output), 'bytes': args.output.stat().st_size,
                    'members': {path.name: sha256(path) for path in members}}
    args.output.with_suffix('.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(f'{len(members)} verified bundle inputs, {manifest["bytes"]} archive bytes, SHA-256 {manifest["archive_sha256"]}')


if __name__ == '__main__':
    main()
