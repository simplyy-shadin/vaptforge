# Guided Startup (v0.8)

VAPTForge v0.8 makes the safe path the easiest path. New users can start with one command:

```bash
vaptforge start
```

The launcher keeps the existing advanced CLI intact while providing two clear modes.

## Guided / Automatic

Guided mode is recommended for normal local use.

It walks through:

1. **Authorization scope** — choose an existing JSON scope or create a new one after explicitly confirming authorization.
2. **Target** — choose a target derived from the scope. Localhost scopes include friendly Juice Shop and DVWA suggestions.
3. **Assessment profile** — choose Quick, Web, Network, or Full instead of typing scanner names.
4. **Tool readiness** — optional external scanner binaries that are not installed are shown and skipped. Built-in checks remain available.
5. **Confirmation** — review target, scope, profile, and scanner list before the job is queued.
6. **Platform startup** — the same SQLite database is used by the background worker and FastAPI dashboard.

The launcher does not bypass scope validation. The selected target is validated before queueing, and the worker validates scope again before every scanner invocation.

## Manual / Advanced

Choose Manual / Advanced when you want to control the queue, worker, or scanner list yourself.

The platform starts the worker and dashboard, then you can use commands such as:

```bash
vaptforge queue-assessment http://127.0.0.1:3000 \
  --scope config/scope.example.json \
  --profile web \
  --db data/vaptforge.db
```

The original `--scanners` option remains available for exact scanner selection.

## Profiles

| Profile | Intended use | Scanner set |
| --- | --- | --- |
| `quick` | Fast baseline with no external binaries required | HTTP, TLS |
| `web` | Web application assessment | HTTP, TLS, httpx, Nikto, Nuclei, ffuf |
| `network` | Host/service-oriented assessment | Nmap, Nuclei |
| `full` | Complete authorized assessment | HTTP, TLS, httpx, Nmap, Nikto, Nuclei, ffuf |

Run:

```bash
vaptforge profile-list
```

to see the profiles and which scanners are ready on the current machine.

In **guided mode**, unavailable optional binaries are skipped with a visible warning. In **manual mode**, profiles retain their intended scanner set so advanced users can detect and troubleshoot missing tools themselves.

## Help

Both standard help forms work:

```bash
vaptforge -h
vaptforge --help
```

Command-specific help also works:

```bash
vaptforge start -h
vaptforge queue-assessment -h
vaptforge scan -h
```

The root help recommends `vaptforge start` first while retaining the lower-level commands for advanced operation.

## Platform supervision

After the launcher completes its choices, VAPTForge supervises two existing components:

- the durable SQLite assessment worker
- the FastAPI dashboard/API

The default dashboard binding remains:

```text
http://127.0.0.1:8000/
```

Press Ctrl+C in the launcher terminal to stop the locally supervised platform processes.

The launcher does not make the dashboard a distributed service and does not weaken the existing API mutation controls.
