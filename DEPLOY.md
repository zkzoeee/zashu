# Deploying to Fly.io (scale-to-zero)

This guide deploys `zashu-mint`, which serves the landing page at `/`, the playground at `/playground`, and the mint API at `/v1/zk/*`. The app runs on one Fly Machine. The machine **suspends when idle** and **wakes on the next request**, so you pay for compute only while someone is using it.

The repo includes:

| File | Purpose |
| :--- | :--- |
| `Dockerfile` | Two-stage build: compiles `zashu-mint` with Rust, then copies the binary into a slim Debian image that runs as a non-root user. |
| `.dockerignore` | Keeps `target/`, `video/` and docs out of the build context. |
| `fly.toml` | App config: auto-stop/auto-start, health check, VM size. |

## 1. One-time setup

```bash
brew install flyctl        # or: curl -L https://fly.io/install.sh | sh
fly auth login
```

App names are global on Fly. If `zashu` is taken, set another name in the `app = "…"` line of `fly.toml`. Also set `primary_region` to a region near your users; `fly platform regions` lists them.

```bash
fly apps create zashu      # use the same name as in fly.toml
```

## 2. Deploy

```bash
fly deploy --ha=false
```

* The image builds on Fly's remote builder, so you don't need Docker locally. The first build takes a few minutes because it compiles the Halo2 proving crates.
* **`--ha=false` matters.** By default `fly deploy` creates two machines for redundancy. Mint state and playground sessions live **in memory**, and each browser tab's session (`X-Zashu-Session`) is tied to one process. With two machines, a tab's requests could land on a machine that has never seen that session. Keep exactly one machine:

```bash
fly scale count 1          # only needed if you ever end up with more than one
```

Make sure the app has public IPs. If `fly ips list` is empty, `<app>.fly.dev` won't resolve. Allocate the free ones; a dedicated IPv4 is the paid option, so skip it:

```bash
fly ips list
fly ips allocate-v6
fly ips allocate-v4 --shared
```

Then open the site:

```bash
fly open                   # https://<app>.fly.dev/
```

## 3. How auto-stop / auto-start works

These settings live in `[http_service]` in `fly.toml`:

```toml
auto_stop_machines   = "suspend"  # idle → suspend (RAM snapshot)
auto_start_machines  = true       # next request → resume
min_machines_running = 0          # allow scaling all the way to zero
```

* Fly's proxy checks every few minutes for machines with no traffic and suspends them. Health checks don't count as traffic, so they won't keep the machine awake.
* When a request arrives for a suspended machine, the proxy resumes it and holds the request until it's ready. Resuming usually takes well under a second. A cold start from `stop` is a bit slower, but this binary starts almost instantly.
* **Why `suspend` and not `stop`:** suspend snapshots memory, so a visitor's playground session and the mint's state survive idle periods. A `stop` restarts the process, which resets the mint and every playground session. Fly falls back to a plain stop when it can't suspend, for example on the first idle after some deploys. The app handles that fine; it just starts fresh.
* Suspend requires **≤ 2 GB RAM and no swap**. If you need more memory or want swap (`swap_size_mb`), switch to `auto_stop_machines = "stop"`.

To check that it's working:

```bash
fly machine list           # STATE shows started / suspended / stopped
fly logs                   # look for "… has no traffic … suspending/stopping"
```

## 4. Sizing

Measured locally:

* Peak memory is about **0.6 GB** during a full playground run on the default Ragu backend (about 0.4 GB with `ZASHU_PCD_BACKEND=halo2`).
* A full playground run takes about **25 s** on a 10-core laptop with Ragu, against about 5 s with Halo 2. Expect it to be several times slower on shared vCPUs; Ragu has not been timed on Fly.
* The single-core timings previously listed here (stealth send about 13 s, melt about 6 s) were measured on Halo 2 and have not been re-measured for Ragu.
* The solvency proof is folded on a background thread, and binding the roots costs about 24 s per shielded swap on a laptop. On small shared CPUs the fold can lag well behind a burst of activity, and `/v1/solvency` waits for it to catch up. `ZASHU_PCD_BACKEND=ragu-unbound` cuts that to about 1 s per operation at the cost of not proving root changes.
* `ZASHU_PCD_BACKEND=ragu-aggregated` needs several GB of RAM (proofs of about 172 MB in flight, 3 GB peak in tests) and about 25 s to start; it does not fit the 2 GB machine.
* **The demo is pinned to Halo 2.** `fly.toml` sets `ZASHU_PCD_BACKEND=halo2` under `[env]`, so a deploy keeps the old speed even though the binary is built with Ragu. That backend does not prove note openings or predicates. Delete the `[env]` entry to run the demo on Ragu.
* The build now fetches Ragu from GitHub (a pinned git dependency), so the Docker build needs network access to `github.com` as well as crates.io. The image builds locally in about 2.5 minutes, and a container limited to 4 CPUs and 2 GB served a Ragu solvency proof in about 3 s.

Proving runs across multiple threads, so more vCPUs make the playground noticeably snappier. The config uses `shared-cpu-4x` with 2 GB. Because the machine scales to zero, you're billed for CPU and RAM only while it's running, plus a small amount for its root filesystem. Lower the size if you want to:

```bash
fly scale vm shared-cpu-2x --memory 1024
```

With less than about 1 GB, proving can run out of memory.

## 5. Keys and demo defaults

The server uses deterministic **dev keys** and a placeholder reserve UTXO unless you pass flags. That's fine for a public demo: it keeps `mint_id` stable across restarts. For anything beyond a demo, pass real keys through the container command, for example with `fly secrets set MINT_SK=… RESERVE_SK=…` plus a wrapper `CMD` that forwards them to `--mint-sk` / `--reserve-sk`. Don't bake keys into the image.

## 6. Custom domain (optional)

```bash
fly certs add zashu.example
```

Then add the DNS records the command prints.
