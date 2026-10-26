#!/usr/bin/env python3
"""Stage an already-tested MVP bundle and sign its release manifest locally.
This command never uploads anything or copies the private key into the release.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--version', type=installer.validate_version, required=True)
    parser.add_argument('--signing-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output already exists; release staging never overwrites an existing version.')
    public = subprocess.check_output(['openssl', 'pkey', '-in', str(args.signing_key), '-pubout'], text=True)
    if public.strip() != installer.PUBLIC_KEY.strip():
        parser.error('Signing key does not match the installer’s pinned public key.')
    with tempfile.TemporaryDirectory() as directory:
        installer.unpack(args.bundle, Path(directory), args.version)
    data = args.bundle.read_bytes()
    schema, platform, asset, supported = installer.release_layout(args.version)
    manifest = {'schema': schema, 'project': installer.PROJECT, 'version': args.version, 'platform': platform, 'asset': {'name': asset, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}}
    if schema == 2:
        manifest['supported_ubuntu'] = supported
    if not 0 < len(data) <= installer.MAX_ARCHIVE:
        parser.error('Invalid archive size.')
    args.output.mkdir(parents=True)
    shutil.copyfile(args.bundle, args.output / asset)
    (args.output / 'release.json').write_text(json.dumps(manifest, indent=2) + '\n')
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(args.signing_key), '-out', str(args.output / 'release.json.sig'), str(args.output / 'release.json')], check=True)
    installer.verify_manifest(args.output / 'release.json', args.output / 'release.json.sig', args.version)
    print(f'Staged and verified release v{args.version} in {args.output}. Publish the three files as release assets.')


if __name__ == '__main__':
    main()
