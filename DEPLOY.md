# Deploying

The server is a single binary (`glitchtip-d`) that embeds the web UI (`public/index.html`) and the schema, so **any
UI change needs a rebuild**. It needs PostgreSQL and runs behind nginx (see `deploy/nginx.conf` and the README).
Target host: Debian 13 (x86_64). Configuration lives in `/etc/glitchtip/env` (template: `deploy/env.example`).

## One-time host setup

    useradd --system glitchtip
    sudo -u postgres createuser glitchtip
    sudo -u postgres createdb -O glitchtip glitchtip
    mkdir -p /opt/glitchtip /etc/glitchtip
    cp deploy/env.example /etc/glitchtip/env        # edit: PUBLIC_URL, TRUST_PROXY=true, BIND_ADDRESS=127.0.0.1, ...
    cp deploy/glitchtip.service /etc/systemd/system/ && systemctl daemon-reload && systemctl enable glitchtip

The service connects to Postgres over the unix socket with peer authentication, so the OS user and database role
share the name `glitchtip` and no password is needed.

## Option A: build with Docker (recommended)

`deploy/Dockerfile.build` builds with LDC 1.42 inside Debian 13, so the binary matches the host's libc/OpenSSL.
It needs access to Docker Hub and GitHub.

    docker build --platform linux/amd64 -f deploy/Dockerfile.build --target out --output type=local,dest=out .
    scp out/glitchtip-d HOST:/opt/glitchtip/glitchtip-d.new

(On a Debian 13 x86_64 host you can run the build on the host itself after rsyncing the source.)

## Option B: bare metal build (no Docker)

Do this on the Debian 13 host. It needs apt and GitHub access; `code.dlang.org` may be unreachable from some hosts.

    apt-get install -y ldc dub gcc libssl-dev zlib1g-dev pkg-config git
    rsync -a dub.sdl dub.selections.json source sql public HOST:/opt/glitchtip/src/    # from your workstation
    cd /opt/glitchtip/src && dub build --compiler=ldc2 -b release

If the host cannot reach `code.dlang.org`, copy the dependency cache from a workstation that has built the project
(`rsync -a ~/.dub/packages/ HOST:/root/.dub/packages/`), delete the copied `local-packages.json`, and build with
`dub build --compiler=ldc2 -b release --skip-registry=all`. The result is `/opt/glitchtip/src/glitchtip-d`.
Long builds over SSH can be dropped by the remote side; run them under `nohup ... &` and poll for the result.

## Installing a new binary

    cd /opt/glitchtip
    cp glitchtip-d glitchtip-d.prev                  # rollback copy
    install -m755 <new binary> glitchtip-d.new && mv glitchtip-d.new glitchtip-d
    systemctl restart glitchtip
    systemctl is-active glitchtip && journalctl -u glitchtip -n 5 --no-pager

The schema is applied automatically at startup. Rollback: `cp glitchtip-d.prev glitchtip-d && systemctl restart glitchtip`.

## Running with Docker at runtime

There is no runtime image; the Dockerfile only produces the binary. To run the app in a container, use any Debian 13
base image, copy `glitchtip-d` in, pass the same variables as `/etc/glitchtip/env` (set `DATABASE_URL`-style settings
from `deploy/env.example` to point at your Postgres) and put it behind nginx as above.
