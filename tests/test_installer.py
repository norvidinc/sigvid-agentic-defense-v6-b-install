import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_supported_hosts_and_legacy_release_restriction(self):
        for version in ('22.04', '24.04'):
            with patch.object(installer.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu', 'VERSION_ID': version}), patch.object(installer.platform, 'machine', return_value='x86_64'):
                installer.validate_host('0.1.1')
                if version == '22.04':
                    with self.assertRaises(installer.InstallError):
                        installer.validate_host('0.1.0')
                else:
                    installer.validate_host('0.1.0')
        for distro, version, arch in [('ubuntu', '20.04', 'x86_64'), ('debian', '22.04', 'x86_64'), ('ubuntu', '22.04', 'aarch64')]:
            with patch.object(installer.platform, 'freedesktop_os_release', return_value={'ID': distro, 'VERSION_ID': version}), patch.object(installer.platform, 'machine', return_value=arch), self.assertRaises(installer.InstallError):
                installer.validate_host('0.1.1')

    def test_fixed_version_only(self):
        self.assertEqual(installer.validate_version('0.1.0'), '0.1.0')
        for value in ['latest', 'v0.1.0', '../main', '0.1.0;id', '01.1.0', '0.1.0/asset']:
            with self.subTest(value=value), self.assertRaises(installer.InstallError):
                installer.validate_version(value)

    def test_release_redirect_allowlist(self):
        installer.validate_download_url('https://release-assets.githubusercontent.com/github-production-release-asset/asset?token=temporary')
        for url in ['http://github.com/x', 'https://attacker.example/x', 'https://github.com.attacker.example/x', 'https://user:secret@github.com/x', 'https://github.com:444/x']:
            with self.subTest(url=url), self.assertRaises(installer.InstallError):
                installer.validate_download_url(url)
        with self.assertRaises(installer.InstallError):
            installer.ReleaseRedirects().redirect_request(None, None, 302, '', {}, 'http://github.com/x')

    def test_signed_manifest_and_wrong_version(self):
        for release in (ROOT / 'releases').iterdir():
            manifest = release / 'release.json'
            signature = release / 'release.json.sig'
            with self.subTest(release=release.name):
                parsed = installer.verify_manifest(manifest, signature, release.name[1:])
                self.assertEqual(parsed['project'], installer.PROJECT)
                with self.assertRaises(installer.InstallError):
                    installer.verify_manifest(manifest, signature, '9.9.9')

    def test_tampered_manifest_or_signature_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, signature = Path(directory) / 'release.json', Path(directory) / 'release.json.sig'
            manifest.write_bytes((ROOT / 'releases/v0.1.0/release.json').read_bytes() + b' ')
            signature.write_bytes((ROOT / 'releases/v0.1.0/release.json.sig').read_bytes())
            with self.assertRaises(installer.InstallError):
                installer.verify_manifest(manifest, signature, '0.1.0')
            manifest.write_bytes((ROOT / 'releases/v0.1.0/release.json').read_bytes())
            signature.write_bytes(b'bad signature')
            with self.assertRaises(installer.InstallError):
                installer.verify_manifest(manifest, signature, '0.1.0')

    def test_changed_archive_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'bundle'
            archive.write_bytes(b'valid artifact')
            manifest = {'asset': {'size': archive.stat().st_size, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}}
            installer.verify_archive(archive, manifest)
            archive.write_bytes(b'tampered bytes')
            with self.assertRaises(installer.InstallError):
                installer.verify_archive(archive, manifest)

    def make_archive(self, path, bad=None):
        with tarfile.open(path, 'w:gz') as archive:
            for name in ['install.py', 'INSTALL.txt', 'SHA256SUMS', 'sigvid-agent_0.1.0_amd64.deb']:
                member = tarfile.TarInfo('sigvid-agent/' + name)
                member.size = 3
                archive.addfile(member, io.BytesIO(b'abc'))
            if bad:
                archive.addfile(bad, io.BytesIO(b''))

    def test_safe_archive_and_layout_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            archive = directory / 'bundle.tar.gz'
            self.make_archive(archive)
            installer.unpack(archive, directory, '0.1.0')
            self.assertEqual((directory / 'sigvid-agent/install.py').read_bytes(), b'abc')
        for name, kind in [('sigvid-agent/../../escape', tarfile.REGTYPE), ('sigvid-agent/install.py', tarfile.REGTYPE), ('sigvid-agent/link', tarfile.SYMTYPE), ('sigvid-agent/install.py', tarfile.LNKTYPE)]:
            with tempfile.TemporaryDirectory() as directory:
                directory = Path(directory)
                archive = directory / 'bundle.tar.gz'
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = '/etc/passwd' if kind != tarfile.REGTYPE else ''
                self.make_archive(archive, member)
                with self.subTest(name=name, kind=kind), self.assertRaises(installer.InstallError):
                    installer.unpack(archive, directory, '0.1.0')
                self.assertFalse((directory / 'sigvid-agent').exists())

    def test_download_size_limit(self):
        class Response(io.BytesIO):
            pass
        class Opener:
            def open(self, request, timeout):
                return Response(b'larger than permitted')
        with tempfile.TemporaryDirectory() as directory, patch.object(installer, 'build_opener', return_value=Opener()):
            with self.assertRaises(installer.InstallError):
                installer.download('https://github.com/asset', Path(directory) / 'file', 4)

    def test_embedded_key_matches_published_key(self):
        self.assertEqual(installer.PUBLIC_KEY.strip(), (ROOT / 'release-public-key.pem').read_text().strip())

    def test_supported_channel_signature_and_immutable_record(self):
        channel = ROOT / 'channels/beta.json'
        signature = ROOT / 'channels/beta.json.sig'
        manifest = installer.verify_channel(channel, signature)
        self.assertEqual(manifest['version'], '0.1.4')
        self.assertEqual(channel.read_bytes(), (ROOT / 'channels/history/beta-000001.json').read_bytes())
        with tempfile.TemporaryDirectory() as directory:
            altered = Path(directory) / 'beta.json'
            altered.write_bytes(channel.read_bytes().replace(b'0.1.4', b'9.9.9'))
            with self.assertRaises(installer.InstallError):
                installer.verify_channel(altered, signature)
        with patch.object(installer, 'verify_signature'):
            for change in [{'channel': 'unreviewed'}, {'revision': 0}, {'version': None}, {'helper_sha256': 'bad'}, {'extra': True}]:
                with tempfile.TemporaryDirectory() as directory:
                    altered = Path(directory) / 'beta.json'
                    altered.write_text(json.dumps(dict(manifest, **change)))
                    with self.assertRaises(installer.InstallError):
                        installer.verify_channel(altered, signature)

    def test_automatic_upgrade_selection_and_distribution_refusals(self):
        raw = (ROOT / 'channels/beta.json').read_bytes()
        manifest = json.loads(raw)
        helper = b'# controlled helper fixture\n'
        manifest['helper_sha256'] = hashlib.sha256(helper).hexdigest()
        target = {'available': True, 'release_sha256': hashlib.sha256(raw).hexdigest()}
        public_calls, private_calls = [], []
        def download(url, destination, limit):
            public_calls.append(url)
            destination.write_bytes(raw if url.endswith('.json') else b'signature fixture')
        def backend(origin, credential, path, limit):
            private_calls.append((origin, credential, path))
            return json.dumps(target).encode() if path.endswith('/target') else helper
        for failure in ('', 'target', 'helper'):
            selected = dict(manifest)
            if failure == 'helper':
                selected['helper_sha256'] = '0' * 64
            target['available'] = failure != 'target'
            with patch.object(installer, 'enrolled_context', return_value=('h_1234567890abcdef', 'https://enrolled.example', 'private-credential')), \
                    patch.object(installer, 'download', side_effect=download), \
                    patch.object(installer, 'verify_channel', return_value=selected), \
                    patch.object(installer, 'backend_read', side_effect=backend), \
                    patch.object(installer.subprocess, 'run') as run:
                if failure:
                    with self.assertRaises(installer.InstallError):
                        installer.upgrade_agent('h_1234567890abcdef', False)
                    run.assert_not_called()
                else:
                    installer.upgrade_agent('h_1234567890abcdef', True)
                    args = run.call_args.args[0]
                    self.assertEqual(args[args.index('--version') + 1], '0.1.4')
                    self.assertEqual(args[args.index('--sha256') + 1], manifest['package']['sha256'])
                    self.assertIn('--check', args)
                    self.assertNotIn('private-credential', ' '.join(args))
        self.assertTrue(all('raw.githubusercontent.com/' + installer.REPOSITORY in u for u in public_calls))
        self.assertTrue(all(origin == 'https://enrolled.example' for origin, _, _ in private_calls))
        self.assertTrue(all('private-credential' not in u for u in public_calls))

    def test_backend_redirect_and_response_bound(self):
        with self.assertRaises(installer.InstallError):
            installer.BackendRedirects().redirect_request(None, None, 302, '', {}, 'https://other.example')
        response = io.BytesIO(b'oversized')
        opener = Mock()
        opener.open.return_value = response
        with patch.object(installer, 'build_opener', return_value=opener), self.assertRaises(installer.InstallError):
            installer.backend_read('https://enrolled.example', 'private', '/agent/upgrade/target', 4)


if __name__ == '__main__':
    unittest.main()
