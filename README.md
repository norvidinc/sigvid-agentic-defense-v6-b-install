# Sigvid Agentic Defense V6 B — MVP installation

Public agent downloads and enrollment client for the **B MVP implementation** in `mvp-v1/`. This repository distributes the installer and release packages. Your Sigvid backend issues enrollment tokens and receives evidence.

Supported host: **Ubuntu Server 24.04 LTS, amd64/x86_64**, with Python 3.12, OpenSSL and sudo. Response mode is **shadow only**. This is an early MVP release with deterministic SSH-failure, watched-file and source-health detections; it does not include adaptive AI investigation.

## Enroll your server

1. Open **Setup** in your Sigvid backend and create a one-time enrollment token for your server name.
2. On the Ubuntu server you want to monitor, download this version's installer:

   ```sh
   curl --fail --show-error --location --proto '=https' --tlsv1.2 \
     https://raw.githubusercontent.com/norvidinc/sigvid-agentic-defense-v6-b-install/v0.1.0/install.py \
     --output sigvid-install.py
   ```

3. Run it with **your reachable backend address**:

   ```sh
   sudo python3 sigvid-install.py --version 0.1.0 \
     --server https://your-sigvid-backend.example.com
   ```

4. Paste the token at the private prompt. Enter the operator IP/CIDR from which you administer the server. SSH port 22 is always protected.
5. Return to **Setup → Verify the connection**. Check the enrolled host, heartbeat, source health and received evidence.

The example backend hostname is a placeholder. A backend on `127.0.0.1` on your workstation is not reachable at that address from another machine. For an isolated lab only, pass its guest-visible address with `--allow-insecure-lab`; public GitHub downloads always require HTTPS.

No GitHub account is needed to download a published public release. GitHub never receives the enrollment token or host credential. Installing the package alone does not grant access to your backend.

## Verification and checks

The installer downloads a fixed version's signed release manifest, verifies its RSA/SHA-256 signature against the public key embedded in the installer, checks the archive's exact size and SHA-256, and permits only the expected regular files before running the bundled installer. The bundled installer checks the `.deb` checksum, supported host and backend connectivity. There is no `latest` fallback, arbitrary repository override, HTTP download, or signature bypass.

The trust anchor is this installer obtained from the intended repository over HTTPS. A verified signature identifies the release signer; it does not establish threat-detection accuracy or eliminate the need to trust that signer. Pin the installer URL to the release tag or a reviewed commit. Keep the release public key fingerprint available through a trusted channel when distributing the installer independently.

Check prerequisites without installing:

```sh
sudo python3 sigvid-install.py --version 0.1.0 \
  --server https://your-sigvid-backend.example.com --check
```

Download and verify without installing or enrolling (does not need sudo):

```sh
python3 sigvid-install.py --version 0.1.0 --download-only ./sigvid-release-0.1.0
```

A failed check stops before enrollment. If the server is already enrolled, its credential is preserved. Diagnose connectivity or service startup with:

```sh
sudo systemctl status sigvid-agent sigvid-executor
sudo journalctl -u sigvid-agent -u sigvid-executor -n 50 --no-pager
```

## What installation changes

The package installs the native agent and restricted executor, creates the `sigvid` service account, grants journal access and directory access for declared file watches, writes configuration under `/etc/sigvid`, and starts two systemd services. The host credential lives under `/var/lib/sigvid` with restricted file permissions. The executor remains in shadow mode and cannot enable live blocking through this UI.

Never commit enrollment tokens, credentials, backend databases, private signing keys, host logs or VM files to this distribution repository. Agent/backend source remains in the implementation project.

## Release maintenance

- Build and validate the B MVP bundle in the implementation project. Reuse the exact tested artifact; do not upload a package from another implementation.
- Run `tools/prepare_release.py` with that archive, a new fixed version and the release signing key stored outside this repository. It stages the archive, `release.json` and `release.json.sig` under an ignored output directory and verifies the signature locally.
- Commit the installer/public key and the signed manifest under `releases/vVERSION/`. Run `python3 -m unittest discover -s tests -v` and review the files to be published.
- Tag the reviewed installer commit. Create a draft GitHub release for that tag, attach the **three staged files**, then publish. Use GitHub release immutability to prevent replacement. Never force-update a published tag or replace an asset; issue a new version.
- Check an anonymous download and run the public installer on the disposable Ubuntu lab against a separate test backend. Connect the backend Setup page to the exact tested installer commit/version.

Example staging command (paths are placeholders):

```sh
python3 tools/prepare_release.py \
  --bundle /path/to/tested/sigvid-agent-ubuntu24.04-amd64.tar.gz \
  --version 0.1.0 \
  --signing-key /secure/location/private.pem \
  --output dist/v0.1.0
```

The signing private key must be backed up securely and never uploaded to GitHub. Key rotation requires a reviewed new installer/public key. The CI workflow tests the public installer with read-only repository permissions; building the private agent and publishing releases remain maintainer operations.
