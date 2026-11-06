# Deployment snippets

## Docker

Build the image on Linux:

```bash
docker build -t htxpro:latest .
# Create a private env file containing a persistent random 256-bit session key.
./deploy/generate-session-secret.sh ./htxpro.env

docker run --rm \
  --env-file "$PWD/htxpro.env" \
  -p 8443:8443/udp \
  -p 8443:8443/tcp \
  -p 8080:8080/tcp \
  --mount type=bind,src="$PWD/certs/fullchain.pem",dst=/run/secrets/tls_cert,readonly \
  --mount type=bind,src="$PWD/certs/privkey.pem",dst=/run/secrets/tls_key,readonly \
  htxpro:latest
```

For multiple domains, either concatenate the fullchains and keys into the two mounted files or mount a certificate directory and configure `tls_cert` and `tls_key` as YAML lists. Certificates are selected by SNI; exact names beat wildcards, and the first chain is the fallback when SNI is absent or unknown. Ensure every private key is readable by the container user (UID 10001).

The image contains `/app/config.yaml`, copied from `deploy/config.docker.yaml`. To use a different configuration, mount it at `/app/config.yaml` or override the command with `--config /path/to/config.yaml`. For any protected virtual host, configure `security.session_secret: "${HTXPRO_SESSION_SECRET}"`; `--env-file` supplies the generated value. Keep `htxpro.env` out of version control and reuse the same file across container recreations so sessions remain valid. The server rejects the published sample placeholder rather than accepting a publicly known signing key. Publish UDP/8443 for HTTP/3, TCP/8443 for whichever secure HTTP protocols are enabled, and optionally TCP/8080 for plain HTTP/1.1 and/or prior-knowledge HTTP/2; do not publish port 8080 unless cleartext traffic is intended to be reachable.

**io_uring is mandatory.** Do not run with `--privileged` as a workaround if the default seccomp profile blocks it; use a reviewed seccomp profile that permits `io_uring_setup`, `io_uring_enter`, and required registration calls. Startup intentionally fails when ring creation is denied. The bundled image enables HTTP/3 over UDP 8443, HTTP/1.1 and HTTP/2 over secure TCP 8443, and HTTP/1.1 plus HTTP/2 prior-knowledge over plain TCP 8080. All listeners use Monoio's required io_uring driver. `http1_secure_enabled` and `http2_secure_enabled` control the secure protocols independently; the secure listener is started if either is enabled. `http1_plain_enabled` and `http2_plain_enabled` independently control protocol support on the shared `plain_listen` address. Cleartext HTTP/2 uses prior-knowledge h2c; HTTP/1.1 Upgrade to h2c is not supported.

## systemd

1. Create a dedicated `htxpro` system user and group.
2. Install the release binary at `/opt/htxpro/bin/htxpro`, configuration at `/opt/htxpro/config.yaml`, and the static roots configured in YAML.
3. When host authentication is enabled, generate a persistent environment file: `sudo ./deploy/generate-session-secret.sh /etc/htxpro/htxpro.env`, then run `sudo chown root:htxpro /etc/htxpro/htxpro.env && sudo chmod 0640 /etc/htxpro/htxpro.env`. Configure `security.session_secret: "${HTXPRO_SESSION_SECRET}"`. Back up this file securely and preserve it across restarts; changing the key invalidates all sessions.
4. Set `tls_cert` and `tls_key` in YAML to either one concatenated PEM path or a list of per-domain paths. Make the configuration readable by `htxpro`; keep private keys readable only by the service account and administrators.
5. Install `htxpro.service` to `/etc/systemd/system/`, then run `systemctl daemon-reload && systemctl enable --now htxpro`.
6. Ensure the service user can read certificate files and all configured static roots. Configure certificate renewal hooks to restart the process after rotation.
7. Confirm the service's seccomp/system-call policy allows io_uring. Do not add a policy that blocks `io_uring_setup`, `io_uring_enter`, or `io_uring_register`.
