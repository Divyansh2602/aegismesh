# Deploying AegisMesh

The console goes to **Vercel** and the API container goes to **Render**. Both are on free
plans, so this needs two accounts and a browser and no card. It is the part of Phase 7 that
cannot be automated from inside the repo.

Everything else is already built and verified: CI is green on Python 3.11 and 3.13, the
image builds and has been run (non-root, and the durable log survives `docker restart` with
a byte-identical root), and `render.yaml` is a Blueprint Render reads directly.

CI runs the unit tests, five of the six scripts in `demo/`, and the standalone verifier.
`demo/phase4_eval.py` is **not** in CI: it needs the optional `[agentdojo]` extra and takes
minutes, so its results are committed to `results/` instead. A change that breaks it will
still show a green check.

---

## Before you start — what the free tier costs, stated once

`render.yaml` is configured for Render's **free** plan. Free instances have an ephemeral
filesystem and cannot attach a persistent disk, so the transparency log runs in memory and
resets whenever the service restarts or wakes from sleep.

**What that costs.** The log growing across two separate visits, and a consistency proof
bridging them, is not demonstrable on this plan. That is a genuine loss and it is worth
naming rather than discovering later.

**What it does not cost, which is the larger claim.** The auditor bundle is pinned as one
snapshot — warrant, receipt and trust anchors fetched together and cached — so a visitor who
downloads it gets 6/6 from `tools/verify_warrant.py` offline, on their own machine, trusting
nobody involved. That bundle is self-contained. The live log resetting an hour later does not
touch the files they already hold. **The headline demonstration survives the free tier
intact**, and Step 5 is where you confirm it against production.

Because the log is honestly in-memory, `/health` reports `log_durable: false` and
`log_persistence: {configured: false, proven: false}` with a note saying why. Nothing in the
deployment claims a property it does not have, which is the only version of this worth
shipping.

### To add durability later

Three things move together in `render.yaml`, and the ordering matters:

1. `plan: free` → `plan: starter` (~$7/mo).
2. Add a `disk:` block mounted at `/data` ($0.25/GB/month).
3. Set `AEGIS_API_LOG_DATABASE` to `/data/aegis-log.sqlite3`.

**Setting 3 without 2 is the one combination to avoid.** `log_durable` would report `true` —
it only checks that a path was configured — while the history silently restarts, so the
service would claim exactly the property it had just lost. `log_persistence` is what
distinguishes them; the verification block in Step 1 explains how to read it.

---

## Step 1 — Render (the API)

1. <https://dashboard.render.com> → **New** → **Blueprint**
2. Connect the repository. Render reads [`render.yaml`](../render.yaml) automatically.
3. Confirm the plan reads **Free**, and that no disk is listed. If Render offers to add one,
   decline — a disk forces a paid instance, and the Blueprint is not set up to use it.
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
a hygiene improvement. This still matters on the free plan: within a single uptime window
the roots handed to visitors are signed with it, and a key that changed per deploy would
orphan every artifact bundle downloaded before the change. The default committed in
`aegis/api/config.py` is published in this repository and must never sign anything that
matters; the service logs a warning if it is used with a durable log.

**Verify:**

```bash
curl -s https://<your-app>.onrender.com/health
```

Expect `"status":"ok"`, and on this plan:

```json
"log_durable": false,
"log_persistence": {"configured": false, "proven": false, "boots": null,
                    "note": "In-memory log: history resets when this process does…"}
```

**That is the correct output here, not a fault.** The free tier has no disk and the service
says so plainly. What you are checking is that it is *honest*, not that it is durable.

The first request may take 30–60 seconds: free instances sleep after 15 minutes idle and the
request that wakes one is the one that waits for it.

> **If you later add the disk**, this is where it gets verified, and it takes a restart on
> purpose. `log_durable` only says storage was *configured* — an `isinstance` check, true
> whenever a path is set, including on a container with no volume behind it. `boots` is a
> counter written into the database file itself, so it is the one piece of evidence that
> survives the thing it measures. Restart from the Render dashboard and check again:
> `"proven": true` with `boots: 2` means the file outlived a process. `boots` still `1`
> means the disk is not attached.

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

**On the free plan this step matters more, not less.** Free instances sleep after 15 minutes
idle, and the in-memory log dies with them — so staying awake is the only thing that lets one
visitor's entry still be there when the next person arrives. It also spares every visitor the
30–60 second cold start. Ten minutes sits comfortably inside the fifteen-minute window.

The second thing it does is record the log's tree size on every ping and compare it to the
previous one. How it reacts depends on what the service claimed about itself:

- `log_durable: true` and the tree shrank → **the run fails.** A service claiming durability
  whose log went backwards has a path with no surviving volume behind it.
- `log_durable: false` and the tree shrank → **recorded as a notice.** That is the documented
  behaviour of an in-memory log, and failing on it would mean a red run every ten minutes for
  a property nothing ever claimed — which is precisely the anti-pattern the `if:` guard above
  exists to avoid.

Stated precisely so it is not oversold: it compares counts, not roots, so it cannot see a
fork or a length-preserving rewrite. It is not a substitute for `aegis/log/witness.py`.

Two GitHub caveats worth knowing rather than discovering: scheduled workflows are
**best-effort** and are frequently delayed under load, and GitHub disables schedules on
repositories with no activity for 60 days.

> **Free-tier budget.** Render gives 750 instance-hours per month across your free services.
> Keeping one service awake continuously uses roughly 730 in a 31-day month, so this fits —
> but only for a single free web service on the account. A second one will exhaust the
> allowance.

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
3. Put the URL at the top of `README.md`. The repository is already public, so this is the
   step that actually makes the demo reachable by anyone reading it.

---

## Known traps, in order of likelihood

| Symptom | Cause |
| --- | --- |
| Console loads but every panel is blank | `AEGIS_API_CORS_ORIGINS` missing, mismatched, or still the placeholder from the Blueprint prompt (Step 3) |
| Vercel build fails immediately | Root Directory not set to `web` (Step 2) |
| `log_persistence.configured: false` | **Expected on the free plan** — `AEGIS_API_LOG_DATABASE` is unset and the log is in memory. Not a fault |
| Log size resets to 0 on its own | Expected on the free plan: the instance slept or redeployed. Keep-warm reduces how often it happens; only a disk removes it |
| `boots` stays `1` across a restart | Only meaningful once you add a disk: the file is being recreated, so the disk is not attached (Step 1) |
| `log_durable: true` on a free instance | A database path is set with no disk behind it. Check the `Dockerfile` as well as `render.yaml` — the path used to be set in both, and removing it from one left the other in charge. `tests/test_deployment_config.py` now guards this |
| `log_durable: true` but history resets | Database path set with no disk behind it. `log_durable` only checks configuration; `log_persistence.proven` is the field that answers this |
| Keep-warm run fails (red, not a notice) | Only happens when `log_durable` is `true` and the tree shrank — a real broken promise. A reset on the free plan is a notice by design |
| First visit after idle hangs ~1 minute | Free-tier cold start; the request that wakes the instance is the one that waits |
| One visitor's traffic rate-limits everyone | `AEGIS_API_TRUST_FORWARDED_FOR` unset — already `true` in the Blueprint |

---

## After it is live

Worth doing, in this order:

1. Visit twice **within one uptime window**, note `tree_size` from `GET /v1/log` each time,
   and fetch `GET /v1/log/consistency?first=<first visit's size>`. The endpoint returns the
   proof and the current signed head.

   On the free plan this only works while the instance stays awake; once it sleeps the log
   restarts at zero and the earlier head belongs to a tree that no longer exists. Do not
   build a demo beat on it here — it is the property the disk buys.

   **Check it rather than reading the proof nodes by eye**, which proves nothing:

   ```bash
   python tools/verify_consistency.py earlier.json later.json trust_anchors.json
   ```

   `earlier.json` is any artifact carrying a head from the first visit — a `receipt.json`
   works unchanged — and `later.json` is the `/v1/log/consistency` response. It holds one
   public key, calls nothing, and reports whether today's tree still contains the one you
   were shown. `tools/verify_warrant.py` cannot do this and says so: it deliberately takes
   no consistency proof, so a receipt older than the root you hold is where it stops.
2. Watch the **Keep warm** workflow's run history. On a durable log it is a third party's
   timestamped record that the tree only ever grew. Here it is weaker but still real: a
   record of uptime, and of every reset, written somewhere the operator does not control.
3. Walk the demo end to end against production once — pick a scenario, watch the
   counterfactuals stream, read the three argument states, attack the warrant, download the
   artifacts and verify them — so the first time it is demonstrated to someone else is not
   the first time it has been done against production.
