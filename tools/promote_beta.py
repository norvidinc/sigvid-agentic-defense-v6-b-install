#!/usr/bin/env python3
"""Prepare one signed beta promotion from already-qualified bytes. Never uploads."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--version', type=installer.validate_version, required=True)
    parser.add_argument('--revision', type=int, required=True)
    parser.add_argument('--signing-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.revision < 1:
        parser.error('Use a new output directory and positive promotion revision.')
    public = subprocess.check_output(['openssl', 'pkey', '-in', str(args.signing_key), '-pubout'], text=True)
    if public.strip() != installer.PUBLIC_KEY.strip():
        parser.error('Signing key does not match the existing installer trust anchor.')
    for field, value in [('Package', 'sigvid-agent'), ('Version', args.version), ('Architecture', 'amd64')]:
        if subprocess.check_output(['dpkg-deb', '--field', str(args.package), field], text=True).strip() != value:
            parser.error('Package metadata does not match this promotion.')
    package, helper = args.package.read_bytes(), args.helper.read_bytes()
    if not 0 < len(helper) <= 131072 or not 0 < len(package) <= installer.MAX_ARCHIVE:
        parser.error('Package or helper exceeds the supported bounds.')
    package_hash = hashlib.sha256(package).hexdigest()
    for history in sorted((ROOT / 'channels/history').glob('beta-*.json')):
        prior = installer.verify_channel(history, history.with_suffix('.json.sig'))
        if args.revision <= prior['revision']:
            parser.error('Promotion revisions must increase; preserve every published history record.')
        if tuple(map(int, args.version.split('.'))) < tuple(map(int, prior['version'].split('.'))):
            parser.error('A supported-version downgrade needs a separate recovery decision.')
        if prior['version'] == args.version and prior['package']['sha256'] != package_hash:
            parser.error('Never replace package bytes under an existing version; issue a new version.')
    manifest = {'schema': 1, 'project': installer.PROJECT, 'channel': 'beta', 'revision': args.revision,
                'version': args.version, 'platform': 'ubuntu-amd64', 'supported_ubuntu': installer.SUPPORTED_UBUNTU,
                'package': {'name': f'sigvid-agent_{args.version}_amd64.deb', 'sha256': package_hash, 'size': len(package)},
                'helper_sha256': hashlib.sha256(helper).hexdigest()}
    args.output.mkdir(parents=True)
    manifest_path, signature = args.output / 'beta.json', args.output / 'beta.json.sig'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(args.signing_key), '-out', str(signature), str(manifest_path)], check=True)
    installer.verify_channel(manifest_path, signature)
    print(f'Prepared beta revision {args.revision}: {args.version}. Qualification and publication remain separate steps.')


if __name__ == '__main__':
    main()
