# Sigvid Agentic Defense V6 Beta — installation and upgrades

Public agent downloads and enrollment client for the **B MVP implementation** in `mvp-v1/`. This repository distributes the installer and release packages. Your Sigvid backend issues enrollment tokens and receives evidence.

Supported host: **Ubuntu Server 22.04 or 24.04 LTS, amd64/x86_64**, with the system Python 3.10 or newer, OpenSSL and sudo. Response mode is **shadow only**. This is an early MVP release with deterministic SSH-failure, watched-file and source-health detections; it does not include adaptive AI investigation.

The supported beta agent is **0.1.4**. The signed `channels/beta.json` selects the
approved version, exact package and upgrade helper. Publishing another tag or
building newer code does not promote it. The installed version is reported by
your device and shown separately in **Devices & agents → Summary → Agent updates**.

## Upgrade an enrolled server

Run this on the enrolled Ubuntu server:

```sh
curl -fsS --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/norvidinc/sigvid-agentic-defense-v6-beta-install/main/install.sh | sudo sh -s -- --upgrade
```

No version argument is needed. The UI provides the same command with a device
check. It selects the signed supported beta release automatically, uses the
agent's saved backend connection, and preserves identity, settings, policy and
evidence. The package and helper must match the signed promotion and the backend
must be configured to serve that same release. GitHub never receives your host
credential. Supported agents are upgraded only when you run the command.

The command retains private recovery material, briefly restarts the services,
and waits for the same device's fresh versions, retained inventory and drained
queue. Running it again with identical installed binaries changes nothing. Newer
installed versions are never automatically downgraded. A failure to confirm is
reported as pending, rather than success. Keep the terminal open until it finishes.
Python performs the checks internally using the system dependency already
installed with the agent; you do not need to paste or maintain a Python program.

Beta 0.1.4 adds native host inventory alongside the three standard sources;
partial visibility is reported explicitly. Optional osquery remains opt-in.
The immutable 0.1.0 and 0.1.1 releases remain available for historical use.

An explicitly published release candidate can be selected for fresh installation
with `--version 0.1.5-rc.1` (use the exact published RC number). Its signed manifest
uses that version; the archive contains Debian's `0.1.5~rc.1` package filename.
The installer verifies the exact RC and refuses a stable or different RC package
in its place. An RC tag does not change the default installation version or the
supported upgrade channel. RC availability and qualification are stated in the
individual release notes; this syntax example does not announce a release.

## Enroll your server

1. Open **Setup** in your Sigvid backend and create a one-time enrollment token for your server name.
2. On the Ubuntu server you want to monitor, download this version's installer:

   ```sh
   curl --fail --show-error --location --proto '=https' --tlsv1.2 \
     https://raw.githubusercontent.com/norvidinc/sigvid-agentic-defense-v6-beta-install/v0.1.4/install.py \
     --output sigvid-install.py
   ```

3. Run it with **your reachable backend address**:

   ```sh
   sudo python3 sigvid-install.py \
     --server https://your-sigvid-backend.example.com
   ```

4. Paste the token at the private prompt. Enter the operator IP/CIDR from which you administer the server. SSH port 22 is always protected.
5. Return to **Setup → Verify the connection**. Check the enrolled host, heartbeat, source health and received evidence.

The example backend hostname is a placeholder. A backend on `127.0.0.1` on your workstation is not reachable at that address from another machine. For an isolated lab only, pass its guest-visible address with `--allow-insecure-lab`; public GitHub downloads always require HTTPS.

No GitHub account is needed to download a published public release. GitHub never receives the enrollment token or host credential. Installing the package alone does not grant access to your backend.

## Verification and checks

Enrollment verifies a fixed release's RSA/SHA-256 signature, exact archive size,
SHA-256 and allowed file layout before running the bundled installer. Upgrades
verify the signed beta promotion and its package/helper hashes. The shell launcher
downloads a pinned installer commit and verifies its hash before running it.
There is no arbitrary newest-build fallback, repository override or signature
bypass. Public downloads require HTTPS. Private backend requests use the saved
HTTPS connection or its pre-existing explicit isolated-lab HTTP setting, with no
credentialed redirects.

The trust anchor is this installer obtained from the intended repository over HTTPS. A verified signature identifies the release signer; it does not establish threat-detection accuracy or eliminate the need to trust that signer. Pin the installer URL to the release tag or a reviewed commit. Keep the release public key fingerprint available through a trusted channel when distributing the installer independently.

Check prerequisites without installing:

```sh
sudo python3 sigvid-install.py \
  --server https://your-sigvid-backend.example.com --check
```

Download and verify without installing or enrolling (does not need sudo):

```sh
python3 sigvid-install.py --download-only ./sigvid-release-0.1.4
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

The supported beta target has a separate, explicit promotion gate. After package
qualification, `tools/promote_beta.py` signs a manifest from the exact package
and reviewed upgrade helper. Commit each revision under `channels/history/` and
copy that revision to `channels/beta.json` with its signature. Copy those exact
bytes and the existing public key into the backend's upgrade package. Its package
configuration must match the signed version, size and digest. Preserve older
promotion records, signing keys and immutable release assets.

Publish the signed package release and validated installer, then promote the
channel and compatible backend. A channel/backend mismatch stops before any
installation. Verify one canary before offering the command to more devices.
Promotion does not start an unattended update. Do not rebuild a different package
under an already-used version or infer support from a GitHub `latest` label.
The broader automatic fleet updater remains outside this manual beta profile.

- Build and validate the B MVP bundle in the implementation project. Reuse the exact tested artifact; do not upload a package from another implementation.
- Run `tools/prepare_release.py` with that archive, a new fixed version and the release signing key stored outside this repository. It stages the archive, `release.json` and `release.json.sig` under an ignored output directory and verifies the signature locally.
- Commit the installer/public key and the signed manifest under `releases/vVERSION/`. Run `python3 -m unittest discover -s tests -v` and review the files to be published.
- Tag the reviewed installer commit. Create a draft GitHub release for that tag, attach the **three staged files**, then publish. Use GitHub release immutability to prevent replacement. Never force-update a published tag or replace an asset; issue a new version.
- Check an anonymous download and run the public installer on the disposable Ubuntu lab against a separate test backend. Connect the backend Setup page to the exact tested installer commit/version.

Example staging command (paths are placeholders):

```sh
python3 tools/prepare_release.py \
  --bundle /path/to/tested/sigvid-agent-ubuntu-amd64.tar.gz \
  --version 0.1.4 \
  --signing-key /secure/location/private.pem \
  --output dist/v0.1.4
```

The signing private key must be backed up securely and never uploaded to GitHub. Key rotation requires a reviewed new installer/public key. The CI workflow tests the public installer with read-only repository permissions; building the private agent and publishing releases remain maintainer operations.
