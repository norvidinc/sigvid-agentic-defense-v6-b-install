#!/usr/bin/env python3
"""Download and verify the Sigvid V6 B MVP agent, then enroll interactively.
Python 3.10+ and OpenSSL are required; installation targets Ubuntu 22.04/24.04 amd64.
No enrollment token or GitHub credential is accepted on the command line.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

REPOSITORY = 'norvidinc/sigvid-agentic-defense-v6-b-install'
DEFAULT_VERSION = '0.1.1'
ASSET = 'sigvid-agent-ubuntu-amd64.tar.gz'
SUPPORTED_UBUNTU = ['22.04', '24.04']
PROJECT = 'sigvid-agentic-defense-v6-b'
MAX_ARCHIVE = 64 * 1024 * 1024
ALLOWED_DOWNLOAD_HOSTS = {'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}
PUBLIC_KEY = '''-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAus1Rm9HS/hWmBc6IVUjm
1RbKA5p0aAJWmpDrgsCaSqavjFF/J6gMSgRY5Tk7HAqGsfW9Fvo0UNVvP3tVWMDH
xO+69VEvGEkOvw2IG9+16tePr/PKAybJHKFnd2qryB+HfSx1x1wu4fdTHJRpBxeh
Ia4VIpWeEnN4fORRW/TDJBfIgapVK/u9IirnUi3nu1XEIoVz+AHcQB6kWWCGpUNI
vQ4hHKMxqGJyFZvq0lzUkimSY+eOPWUA6ja8fC8zP6GgcFaaK31V74TGCOPwlap/
MyxE8oDj0DZlogwNjlSY57G+ZS6fUKCeZjjAw2yeCbDxkhg1FK77bdkfSUCMEor1
8YrFMxK9s5J5mZYgPvST2ig/3vM2XL1dzOtumz3Q3nORq+ZhYb/NSRytCjMBVuDs
RWJaim1K/U8L4BdnA6Ql0rKA117hextVnZrado40jzKC2nHmvIjDBLEzhnHzFyUf
6CClGHHLZi1WCILtL3ogZkspe3cVP7PmEvytHhDOOajHAgMBAAE=
-----END PUBLIC KEY-----
'''


class InstallError(Exception):
    pass


def validate_version(value):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise InstallError('Use a fixed version such as 0.1.0; latest and arbitrary URLs are not accepted.')
    return value


def release_layout(version):
    # Keep the immutable original release verifiable with the new bootstrap.
    if version == '0.1.0':
        return 1, 'ubuntu-24.04-amd64', 'sigvid-agent-ubuntu24.04-amd64.tar.gz', ['24.04']
    return 2, 'ubuntu-amd64', ASSET, SUPPORTED_UBUNTU


def validate_host(version):
    release = platform.freedesktop_os_release()
    if (release.get('ID') != 'ubuntu' or release.get('VERSION_ID') not in release_layout(version)[3]
            or platform.machine() != 'x86_64'):
        supported = ' or '.join(release_layout(version)[3])
        raise InstallError(f'Release {version} requires Ubuntu {supported} LTS on amd64/x86_64.')


def validate_download_url(value):
    parsed = urlparse(value)
    if (parsed.scheme != 'https' or parsed.hostname not in ALLOWED_DOWNLOAD_HOSTS
            or parsed.username or parsed.password or parsed.port not in (None, 443)):
        raise InstallError('Refusing an unexpected release download destination.')
    return value


class ReleaseRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_download_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, limit):
    validate_download_url(url)
    request = Request(url, headers={'User-Agent': 'Sigvid-V6-B-Installer/1'})
    with build_opener(ReleaseRedirects()).open(request, timeout=30) as response:
        size = 0
        with destination.open('xb') as target:
            while chunk := response.read(65536):
                size += len(chunk)
                if size > limit:
                    raise InstallError('Release download exceeded its size limit.')
                target.write(chunk)


def verify_manifest(path, signature, version):
    if not shutil.which('openssl'):
        raise InstallError('OpenSSL is required to verify the release signature.')
    if path.stat().st_size > 65536 or signature.stat().st_size > 4096:
        raise InstallError('Release manifest or signature is too large.')
    with tempfile.TemporaryDirectory(prefix='sigvid-signature-') as directory:
        key = Path(directory) / 'public.pem'
        key.write_text(PUBLIC_KEY)
        result = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(key), '-signature', str(signature), str(path)], capture_output=True, check=False)
    if result.returncode:
        raise InstallError('Release signature verification failed. Nothing will be installed.')
    manifest = json.loads(path.read_text())
    if not isinstance(manifest, dict):
        raise InstallError('Invalid release manifest.')
    asset = manifest.get('asset')
    schema, target, name, supported = release_layout(version)
    if (manifest.get('schema') != schema or manifest.get('project') != PROJECT
            or manifest.get('version') != version or manifest.get('platform') != target
            or (schema == 2 and manifest.get('supported_ubuntu') != supported)
            or not isinstance(asset, dict) or asset.get('name') != name
            or not isinstance(asset.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', asset['sha256'])
            or type(asset.get('size')) is not int or not 0 < asset['size'] <= MAX_ARCHIVE):
        raise InstallError('Release manifest does not match this project, version or platform.')
    return manifest


def verify_archive(path, manifest):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(65536):
            digest.update(chunk)
    if path.stat().st_size != manifest['asset']['size'] or digest.hexdigest() != manifest['asset']['sha256']:
        raise InstallError('Package archive does not match the signed release manifest.')


def unpack(path, destination, version):
    expected = {'sigvid-agent/install.py', 'sigvid-agent/INSTALL.txt', 'sigvid-agent/SHA256SUMS', f'sigvid-agent/sigvid-agent_{version}_amd64.deb'}
    with tarfile.open(path, 'r:gz') as archive:
        seen, directories, members = set(), set(), []
        total = 0
        for member in archive:
            if member.isdir() and member.name == 'sigvid-agent' and member.name not in directories:
                directories.add(member.name)
                continue
            if member.name not in expected or member.name in seen or not member.isfile():
                raise InstallError('Unexpected, duplicate or unsafe file in release archive.')
            total += member.size
            if member.size < 0 or total > 128 * 1024 * 1024:
                raise InstallError('Expanded release archive exceeded its size limit.')
            seen.add(member.name)
            members.append(member)
        if seen != expected:
            raise InstallError('Release archive is incomplete or contains the wrong package version.')
        target_dir = destination / 'sigvid-agent'
        target_dir.mkdir(mode=0o700)
        # Copy only explicitly allowed regular files; never apply archive paths,
        # ownership, executable bits, links or other filesystem metadata.
        for member in members:
            with archive.extractfile(member) as source, (destination / member.name).open('xb') as target:
                shutil.copyfileobj(source, target)
    return target_dir


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', default=DEFAULT_VERSION, type=validate_version)
    parser.add_argument('--server', help='Your own Sigvid backend HTTPS origin; otherwise prompted')
    parser.add_argument('--allow-insecure-lab', action='store_true', help='Allow HTTP only to your isolated lab backend')
    parser.add_argument('--check', action='store_true', help='Verify release and host/backend prerequisites; do not install')
    parser.add_argument('--download-only', type=Path, metavar='NEW_DIRECTORY', help='Save verified release files; do not install or enroll')
    args = parser.parse_args()
    if sys.version_info < (3, 10):
        raise InstallError('Python 3.10 or newer is required; use the supported Ubuntu system Python.')
    if not args.download_only and os.geteuid() != 0:
        raise InstallError('Run with sudo on the Ubuntu server, or use --download-only DIRECTORY.')
    if not args.download_only:
        validate_host(args.version)
    if args.download_only and args.download_only.exists():
        raise InstallError('Download directory already exists; choose a new directory to preserve existing files.')
    if not shutil.which('openssl'):
        raise InstallError('Install OpenSSL before running this installer.')
    base = f'https://github.com/{REPOSITORY}/releases/download/v{args.version}'
    print(f'Downloading Sigvid V6 B MVP {args.version} from {REPOSITORY}…', flush=True)
    with tempfile.TemporaryDirectory(prefix='sigvid-release-') as directory:
        temporary = Path(directory)
        manifest_path, signature = temporary / 'release.json', temporary / 'release.json.sig'
        download(base + '/release.json', manifest_path, 65536)
        download(base + '/release.json.sig', signature, 4096)
        manifest = verify_manifest(manifest_path, signature, args.version)
        archive = temporary / manifest['asset']['name']
        download(base + '/' + archive.name, archive, manifest['asset']['size'])
        verify_archive(archive, manifest)
        bundle = unpack(archive, temporary, args.version)
        print('Release signature, archive checksum and package layout verified.', flush=True)
        if args.download_only:
            args.download_only.mkdir(mode=0o700, parents=True)
            for source in (manifest_path, signature, archive):
                shutil.copyfile(source, args.download_only / source.name)
            print(f'Verified release saved to {args.download_only.resolve()}. No installation or enrollment performed.')
            return
        command = [sys.executable, str(bundle / 'install.py')]
        if args.server:
            command += ['--server', args.server]
        if args.allow_insecure_lab:
            command += ['--allow-insecure-lab']
        if args.check:
            command += ['--check']
        # The bundled installer reads the enrollment token privately from the
        # terminal. Tokens are never sent to GitHub or put in command arguments.
        subprocess.run(command, check=True)


if __name__ == '__main__':
    try:
        main()
    except (InstallError, ValueError, OSError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        print('Installation stopped: ' + str(exc), file=sys.stderr)
        sys.exit(1)
