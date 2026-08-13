# Deploying AegisMesh

The console goes to **Vercel**, the API container goes to **Render**, and the transparency
log lives on a Render disk. Everything in this file needs an account, a browser and — for
the disk — a card; it is the part of Phase 7 that cannot be automated from inside the repo.

Everything else is already built and verified: CI is green on Python 3.11 and 3.13, the
image builds and has been run (non-root, and the durable log survives `docker restart` with
a byte-identical root), and `render.yaml` is a Blueprint Render reads directly.

---

## Before you start — two decisions

### The disk is not optional and it is not free

Render's free instances have an ephemeral filesystem and sleep after 15 minutes idle, so on
a free plan the transparency log resets every time the service wakes. That does not merely
lose data: it destroys the one property a returning visitor can test personally — that the
tree grew between two visits and still verifies against the head they were given — which is
the most convincing artifact this project has.

Persistent disks require a paid instance (~$7/mo) plus $0.25/GB/month.

**If you would rather not pay yet, delete the `disk:` block *and*
`AEGIS_API_LOG_DATABASE` from `render.yaml` together.** Setting the path with no disk behind
it is the worst of the three options: `/health` reports `log_durable: true` while the
history silently restarts, so the site claims a property it does not have.

### Read the repo as a stranger first

`README.md` and `docs/THREAT_MODEL.md` changed substantially. Open the repository on GitHub
and read them before flipping it public — rendering, ordering and the first screenful are
easier to judge there than locally.

---

## Step 1 — Render (the API)

1. <https://dashboard.render.com> → **New** → **Blueprint**
2. Connect the repository. Render reads [`render.yaml`](../render.yaml) automatically.
3. Confirm the **Starter** plan and the 1 GB disk mounted at `/data`.
4. Apply.

`AEGIS_API_LOG_SEED` is generated once by Render and kept stable across deploys, which is
the actual requirement: it must be secret *and* unchanging. A log whose signing key changes
is a log whose entire signed history stops verifying, so rotating it is a break rather than
a hygiene improvement. The default committed in `aegis/api/config.py` is published in this
repository and must never sign a durable log; the service logs a warning if it is.

**Verify:**

```bash
curl -s https://<your-app>.onrender.com/health
```

Expect `"status":"ok"` and **`"log_durable":true`**. If durability is `false`, the disk did
not attach — fix that before going any further, because every later step assumes the log
persists.

---

## Step 2 — Vercel (the console)

1. <https://vercel.com/new> → import the repository.
2. **Root Directory: `web`.** Easy to miss, and the build fails without it.
3. Environment variable:
   - `NEXT_PUBLIC_AEGIS_API` = `https://<your-app>.onrender.com`
4. Deploy.

`NEXT_PUBLIC_` is required because the console calls the API from the browser, so the value
is compiled into the client bundle and is public by construction. Nothing secret belongs
behind that prefix, and the API holds no credential to leak anyway.

---

## Step 3 — CORS, the step that silently breaks everything

Render → your service → **Environment**:

- `AEGIS_API_CORS_ORIGINS` = `https://<your-project>.vercel.app`

Exact origin, **no trailing slash**. Saving triggers a redeploy.

**Verify:**

```bash
curl -s -D - -o /dev/null https://<your-app>.onrender.com/health \
  -H "Origin: https://<your-project>.vercel.app" | grep -i access-control
```

You must see `access-control-allow-origin`. Without it the console renders every panel
blank: it talks to the API from the browser and fails at the preflight, which looks like a
broken site rather than a configuration gap.

`AEGIS_API_TRUST_FORWARDED_FOR=true` is already set in the Blueprint, because Render
terminates TLS at its proxy and every request otherwise arrives from one internal address —
which would put every visitor in a single rate-limit bucket. It stays off by default
everywhere else, since honouring `X-Forwarded-For` when you are not behind a proxy you
control lets a caller choose its own bucket, which is worse than having no limiter because
it looks like one.

---

## Step 4 — keep-warm

GitHub → **Settings → Secrets and variables → Actions → Variables** → New repository
variable:

- `AEGIS_API_URL` = `https://<your-app>.onrender.com`

Then **Actions → Keep warm → Run workflow** to test it immediately rather than waiting for
the schedule. Until this variable exists the workflow skips cleanly by design — a monitor
that fails every ten minutes before you have deployed only teaches you to ignore it.

On a paid instance this is not needed for warmth, since paid services do not sleep. It earns
its place through the second thing it does: every ping records the log's tree size and
**fails if the log shrank**, which is an append-only violation observed from outside the
operator's own infrastructure. Stated precisely so it is not oversold — it compares counts,
not roots, so it cannot see a fork or a length-preserving rewrite. It is not a substitute for
`aegis/log/witness.py`.

---

## Step 5 — prove it, then go public

1. Open the site and run a scenario end to end.
2. Download `warrant.json`, `receipt.json` and `trust_anchors.json` from the auditor view,
   then run the standalone verifier against the files the **deployed** site produced:

   ```bash
   python tools/verify_warrant.py warrant.json receipt.json trust_anchors.json
   ```

   **6/6 is the entire pitch.** Confirm it against production, not only locally — the whole
   claim is that a stranger who trusts nobody can check it on their own machine.
3. Put the URL at the top of `README.md`.
4. GitHub → Settings → **Change visibility → Public**.

---

## Known traps, in order of likelihood

| Symptom | Cause |
| --- | --- |
| Console loads but every panel is blank | `AEGIS_API_CORS_ORIGINS` missing or mismatched (Step 3) |
| Vercel build fails immediately | Root Directory not set to `web` (Step 2) |
| `/health` reports `log_durable: false` | No disk attached — free instance (Step 1) |
| First visit after idle hangs ~1 minute | Free-tier cold start; paid instances do not sleep |
| One visitor's traffic rate-limits everyone | `AEGIS_API_TRUST_FORWARDED_FOR` unset — already `true` in the Blueprint |
| Log resets between visits | `AEGIS_API_LOG_DATABASE` set with no disk behind it |

---

## After it is live

Worth doing, in this order:

1. Visit twice with a gap and check `GET /v1/log/consistency?first=N` bridges the head you
   were given the first time to the one you get the second. That is the property the whole
   log exists for and the only one that needs elapsed time to demonstrate.
2. Watch the **Keep warm** workflow's run history — it becomes a third party's timestamped
   record that the tree only ever grew.
3. Re-run the five-act demo from `HANDOFF.md` against production once, so the first time you
   walk an interviewer through it is not the first time it has been done live.
