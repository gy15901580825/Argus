# Deploy Argus Challenge

These instructions describe the settings for Azure Container Apps. The deployment
operator applies them after live-model validation. Building and checking this image
does not validate the levels against a real model.

Build with `docker build --tag challenge:release challenge/` from the repository
root, then publish the image to the deployment registry. Use the immutable image
digest when creating the app revision.

## App settings

Use generic resource names such as `challenge-app`, `challenge-storage` and
`challenge-data` in the existing container app environment.

| Setting | Value |
| --- | --- |
| Minimum replicas | `0`, to scale to zero when idle |
| Maximum replicas | `1` |
| Revision mode | Single; never run overlapping revisions against the share |
| Process count | One worker; keep the image command |
| Ingress | External, HTTP, target port `8080`; require HTTPS |
| Health probes | HTTP GET `/healthz` on port `8080` for startup, readiness and liveness |
| Startup probe | Allow at least 30 seconds for the mounted database to open |
| Data volume | Azure Files SMB share mounted at `/data`, read/write |

One replica and one process keep the session worlds, submission limits and
database writer in one place. When replacing a revision, stop its replica before
starting the replacement. Scale-to-zero clears in-memory sessions but retains
the database's daily usage, anonymous counters and consented winning attacks.

## Environment

| Variable | Value |
| --- | --- |
| `CHALLENGE_ENV` | `production` |
| `CHALLENGE_TRUST_PROXY` | `true` |
| `CHALLENGE_DB_PATH` | `/data/challenge.sqlite3` |
| `CHALLENGE_MODEL_BASE` | Internal model proxy base URL, for example `http://model-proxy.internal.example` |
| `CHALLENGE_MODEL` | Dedicated deployment name, for example `challenge-deployment` |
| `CHALLENGE_ASSESSMENT_URL` | Final HTTPS assessment page for AT Helper |
| `CHALLENGE_DAILY_BUDGET` | `20`, unless the operator has an approved replacement |

The proxy accepts `/openai/v1/chat/completions`, supplies model authentication and
uses a dedicated deployment with a low throughput limit. The challenge app needs
no model key. Set accounting coefficients to match the selected deployment.
Production refuses `CHALLENGE_MODEL=scripted` and requires a model proxy base URL.

The image runs with `--no-proxy-headers`. Enable application proxy trust only
behind the trusted ingress that appends the client IP to `X-Forwarded-For`;
the app uses the right-most entry for submission limits.

## Shared database mount

Register the SMB share as environment storage and mount it read/write at `/data`.
The mount must use **`nobrl`** to disable SMB byte-range locking. Set this in the
volume's mount options, and verify the effective mount options before accepting
traffic. If the environment cannot apply `nobrl`, do not deploy with that mount.

The container runs as UID and GID `10001`. Grant that identity permission to
create, update and delete files in `/data`; where supported, use mount options
`nobrl,uid=10001,gid=10001,dir_mode=0700,file_mode=0600`.
Mounting a volume replaces the image's directory permissions, so check the
mounted directory rather than relying on its image ownership.

The store sets `journal_mode=DELETE` on every connection and waits up to ten
seconds for a busy database. WAL is unsuitable for this network share. The
directory must permit creation and deletion of the rollback journal next to
`challenge.sqlite3`. Never share this database with another writer. Back up the
database while the app is stopped, and retain the mounted share across revisions
and scale-to-zero events.

## Domain and acceptance

Bind the approved custom domain to the app's external ingress. Create the DNS
records and domain validation record requested by the platform, provision a
managed certificate and bind it to the domain. Require HTTPS for secure session
cookies. Keep resource, deployment and domain examples generic in public notes.

Before opening public traffic, the deployment operator verifies the effective
`nobrl` mount, UID/GID write access, persistent usage after scale-to-zero, health
probes, HTTPS and the custom-domain certificate. Live-model validation and the
deployment itself are separate operator tasks.
