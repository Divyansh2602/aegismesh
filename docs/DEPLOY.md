# Deploying AegisMesh

The console goes to **Vercel**, the API container goes to **Render**, and the transparency
log lives on a Render disk. Everything in this file needs an account, a browser and — for
the disk — a card; it is the part of Phase 7 that cannot be automated from inside the repo.

Everything else is already built and verified: CI is green on Python 3.11 and 3.13, the
image builds and has been run (non-root, and the durable log survives `docker restart` with
a byte-identical root), and `render.yaml` is a Blueprint Render reads directly.

CI runs the unit tests, five of the six scripts in `demo/`, and the standalone verifier.
`demo/phase4_eval.py` is **not** in CI: it needs the optional `[agentdojo]` extra and takes
minutes, so its results are committed to `results/` instead. A change that breaks it will
still show a green check.

---

## Before you start — two decisions

### The disk is not optional and it is not free

Render's free instances have an ephemeral filesystem and sleep after 15 minutes idle, so on
a free plan the transparency log resets every time the service wakes. That does not merely
lose data: it destroys the one property a returning visitor can test personally — that the
tree grew between two visits and still verifies against the head they were given — which is
the most convincing artifact this project has.

Persistent disks require a paid instance (~$7/mo) plus $0.25/GB/month.

**If you would rather not pay yet, three things change together in `render.yaml`:**

1. `plan: starter` → `plan: free` — **easy to miss, and skipping it bills you anyway.**
   Deleting only the disk leaves a paid instance with no disk: the worst of both.
2. Delete the `disk:` block.
3. Delete `AEGIS_API_LOG_DATABASE`.

Deleting the disk while leaving the database path set is the one combination to avoid:
`log_durable` reports `true` — it only checks that a path was configured — while the history
silently restarts, so the service claims a property it does not have. `log_persistence` in
`/health` is what actually distinguishes them, and Step 1 explains how to read it.

On the free path, also **skip Step 4**: the keep-warm workflow fails on a log that resets,
and a monitor that fails every ten minutes only teaches you to ignore it. That is explained
where it matters, in Step 4.

### Read the repo as a stranger first

`README.md` and `docs/THREAT_MODEL.md` changed substantially. Open the repository on GitHub
and read them before flipping it public — rendering, ordering and the first screenful are
easier to judge there than locally.

---

## Step 1 — Render (the API)

1. <https://dashboard.render.com> → **New** → **Blueprint**
2. Connect the repository. Render reads [`render.yaml`](../render.yaml) automatically.
3. Confirm the **Starter** plan and the 1 GB disk mounted at `/data`.
4. **It will prompt for `AEGIS_API_CORS_ORIGINS`**, which is declared `sync: false` with no
   value and therefore asked for during apply — two steps before you can know it, because
   Vercel does not exist yet. Enter a placeholder such as `http://localhost:3000` and
   correct it in Step 3. Do not leave it blank and assume Step 3 will fill it: Render will
   not overwrite a `sync: false` variable on redeploy, so whatever you type here persists
   until you change it by hand.
5. Apply.

`AEGIS_API_LOG_SEED` is generated once by Render and kept stable across deploys, which is
the actual requirement: it must be secret *and* unchanging. A log whose signing key changes
is a log whose entire signed history stops verifying, so rotating it is a break rather than
a hygiene improvement. The default committed in `aegis/api/config.py` is published in this
repository and must never sign a durable log; the service logs a warning if it is.

**Verify — and this takes a restart, on purpose:**

```bash
curl -s https://<your-app>.onrender.com/health
```

Expect `"status":"ok"`. Then look at `log_persistence`, **not** `log_durable`:

```json
"log_persistence": {"configured": true, "proven": false, "boots": 1, "note": "First start…"}
```

`log_durable` only says durable storage was *configured*. It is an `isinstance` check and is
true whenever a database path is set — including on a container with no volume behind that
path, where SQLite works perfectly and the file vanishes on the next restart. Gating on it
would pass in exactly the case worth catching.

`boots` is a counter written into the database file itself, so it is the one piece of
evidence that survives the thing it measures. **Restart the service from the Render
dashboard, then check again:**

```bash
curl -s https://<your-app>.onrender.com/health
```

- `"proven": true` with `boots: 2` → the file outlived a process. The disk is real.
- `boots` still `1` after a restart → the file was recreated. **The disk is not attached**,
  and history will reset every time the service sleeps or redeploys.

Do this before Step 2. Every later step assumes the log persists, and this is the only check
that establishes it rather than assuming it.

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

**Verify the preflight, not a plain GET.** A simple `GET` with an `Origin` header is
answered from the allowed-origins list alone and passes even when the console's real traffic
would fail. The console sends `X-Aegis-Session` and `Content-Type: application/json`, which
makes the browser issue an `OPTIONS` preflight checked against the allowed **methods** and
**headers** as well. Test the request the browser actually makes:

```bash
curl -s -D - -o /dev/null -X OPTIONS https://<your-app>.onrender.com/v1/runs \
  -H "Origin: https://<your-project>.vercel.app" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: x-aegis-session,content-type" \
  | grep -i access-control
```

You need `access-control-allow-origin` echoing your exact origin **and**
`access-control-allow-headers` listing `X-Aegis-Session`. Missing either renders every panel
blank, which looks like a broken site rather than a configuration gap.

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

> **Skip this step entirely if you took the free, no-disk path.** The workflow fails when
> the log shrinks, and a log with no disk behind it shrinks on every restart — so it would
> fail every ten minutes, permanently, which is the exact anti-pattern the guard above
> exists to avoid. Set `AEGIS_API_URL` only once the log persists (Step 1 proves it).

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
   then run the standalone verifier against the files the **deployed** site produced. The
   verifier imports `aegis`, so it needs the package installed, and it takes paths — point
   it at wherever the browser actually put the downloads:

   ```bash
   pip install -e .                      # once, in a checkout of this repo
   python tools/verify_warrant.py \
       ~/Downloads/warrant.json \
       ~/Downloads/receipt.json \
       ~/Downloads/trust_anchors.json
   ```

   **6/6 is the entire pitch.** Confirm it against production, not only locally — the whole
   claim is that a stranger who trusts nobody can check it on their own machine.
3. Put the URL at the top of `README.md`.
4. GitHub → Settings → **Change visibility → Public**.

---

## Known traps, in order of likelihood

| Symptom | Cause |
| --- | --- |
| Console loads but every panel is blank | `AEGIS_API_CORS_ORIGINS` missing, mismatched, or still the placeholder from the Blueprint prompt (Step 3) |
| Vercel build fails immediately | Root Directory not set to `web` (Step 2) |
| `boots` stays `1` across a restart | **No disk attached.** The file is being recreated (Step 1) |
| `log_persistence.configured: false` | `AEGIS_API_LOG_DATABASE` is empty — in-memory log |
| `log_durable: true` but history resets | Database path set with no disk behind it. `log_durable` only checks configuration; `log_persistence.proven` is the field that answers this |
| Keep-warm fails every 10 minutes | The log is resetting, so the tree shrinks. Fix durability or skip Step 4 |
| First visit after idle hangs ~1 minute | Free-tier cold start; paid instances do not sleep |
| One visitor's traffic rate-limits everyone | `AEGIS_API_TRUST_FORWARDED_FOR` unset — already `true` in the Blueprint |

---

## After it is live

Worth doing, in this order:

1. Visit twice with a gap, note `tree_size` from `GET /v1/log` each time, and fetch
   `GET /v1/log/consistency?first=<first visit's size>`. The endpoint returns the proof and
   the current signed head.

   **Be clear about what that shows on its own: not much.** `tools/verify_warrant.py`
   deliberately holds only two public keys and one root and says so — it does not take a
   consistency proof, and there is no CLI in this repo that checks one. Reading the proof
   nodes by eye proves nothing. What you *can* confirm without new tooling is the weaker but
   still useful pair: `tree_size` never decreased, and a receipt issued on the first visit
   still verifies on the second. A CLI that verifies a consistency proof between two heads
   is a genuine gap and is worth building before this is used as a demo beat.
2. Watch the **Keep warm** workflow's run history — it becomes a third party's timestamped
   record that the tree only ever grew.
3. Walk the demo end to end against production once — pick a scenario, watch the
   counterfactuals stream, read the three argument states, attack the warrant, download the
   artifacts and verify them — so the first time it is demonstrated to someone else is not
   the first time it has been done against production.
