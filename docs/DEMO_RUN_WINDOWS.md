# Running the live demo on Windows (cmd.exe, copy-paste)

This is the click-by-click version of [DEMO_WALKTHROUGH.md](DEMO_WALKTHROUGH.md) for this
machine. Every command uses the full path to `uv`, so it works in a plain Command Prompt
without changing `PATH`. The database already has the `admin` user and an **active**
`web_attack_classifier` model, so you only start programs — no setup.

`uv` lives here on this PC:

```
C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts\uv.exe
```

> If you prefer short commands, run this once **in each** Command Prompt window first:
>
> ```cmd
> set PATH=%PATH%;C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts
> ```
>
> then drop the long path and just type `uv ...`. The rest of this guide spells out the full
> path so it always works.

Open each step in its **own** Command Prompt window and leave it running. Start every window
from the project folder:

```cmd
cd /d E:\Data_mining_project
```

---

## Step 0 — make sure PostgreSQL is running (once)

```cmd
cd /d E:\Data_mining_project
pg_ctl -D .local\pgdata status
```

If it says no server is running, start it:

```cmd
pg_ctl -D .local\pgdata -l .local\pg.log -o "-p 5432 -c listen_addresses=localhost" start
```

(If `pg_ctl` is not recognized, PostgreSQL is not on PATH; start it the way you normally do.)

---

## Window 1 — API (the dashboard's data)

```cmd
cd /d E:\Data_mining_project
"C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts\uv.exe" run --project backend uvicorn app.main:app --port 8000
```

Wait for `Application startup complete`. Check it in a browser:c
should show `{"status":"ok", ...}`.

## Window 2 — Worker (scoring and alerting)

```cmd
cd /d E:\Data_mining_project
"C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts\uv.exe" run --project backend cti worker
```

## Window 3 — Demo target website

```cmd
cd /d E:\Data_mining_project
"C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts\uv.exe" run --project backend cti demo-site
```

It prints the serving address and log path. Open the shop at [http://127.0.0.1:8800](http://127.0.0.1:8800).

## Window 4 — Live log follower (feeds new requests into the system)

```cmd
cd /d E:\Data_mining_project
"C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts\uv.exe" run --project backend cti tail --log data\demo\demoshop.access.log --from-end --process
```

Each time you use the demo site, this window prints a line like `{"ingested": 2, ...}`.

## Window 5 — Dashboard

* [ ] 
  ```cmd
  cd /d E:\Data_mining_project\frontend
  npm run dev
  ```

Open the URL it prints ([http://localhost:5173](http://localhost:5173)), sign in as **admin**, and turn on the **Live**
switch in the top bar so the pages refresh by themselves.

> If `npm` is not recognized, Node.js is not on this window's PATH. Open a new Command Prompt
> (Node adds itself to PATH on install) or start the dashboard from the terminal you normally use
> for `npm`.

---

## Driving attacks (for the demo)

**By hand** — open [http://127.0.0.1:8800](http://127.0.0.1:8800) and type payloads into the forms:

| Page               | Field | Example payload                | Expected class |
| ------------------ | ----- | ------------------------------ | -------------- |
| Search             | q     | `1' OR '1'='1' --`           | SQLI           |
| Search             | q     | `<script>alert(1)</script>`  | XSS            |
| Status (`/ping`) | host  | `127.0.0.1; cat /etc/passwd` | CMDI           |
| Downloads          | file  | `../../../../etc/passwd`     | PATH_TRAVERSAL |

Each shows up on the dashboard **Classification** page within a few seconds. Two attack-like
values from the same browser raise an **Alert** on the Alerts page. The demo site only echoes
your input as text — nothing is executed.

**Automatically** — write a burst of 60 requests (~30% attacks) at 4 per second, in a spare
window:

```cmd
cd /d E:\Data_mining_project
"C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts\uv.exe" run --project backend cti demo-traffic --count 60 --attack-ratio 0.3 --rate 4
```

Change `--count` for more/fewer lines, `--rate` for speed (drop `--rate` to write them all at
once), or `--attack-ratio 0.5` for more attacks.

---

## Checking it worked without the dashboard (optional)

```cmd
cd /d E:\Data_mining_project
"C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts\uv.exe" run --project backend cti tail --log data\demo\demoshop.access.log --once --process
```

The printed summary shows `parameters_scored` and `alerts_created`.

---

## Stopping

Press `Ctrl+C` in each of the five windows. The demo log in `data\demo\` is git-ignored; delete
that folder to start clean. The database keeps events, predictions, and alerts until you drop it
(see [DEPLOYMENT_GUIDE.md](../DEPLOYMENT_GUIDE.md) §10).

## If something does not work

- **Dashboard shows no data / errors:** confirm Window 1 (API) still says it is running and
  [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) responds. The API can be killed if the PC runs very low
  on memory — close other apps and restart Window 1.
- **Sign-in fails / password forgotten:** `create-admin` cannot reset an existing user, so make
  a **new** admin with a different name and a password you choose (it prompts twice):

  ```cmd
  cd /d E:\Data_mining_project
  "C:\Users\VANSH\AppData\Roaming\Python\Python312\Scripts\uv.exe" run --project backend cti create-admin --username admin2
  ```

  Then sign in as `admin2`.
- **`uv` not recognized:** you are using the short form without the `set PATH` line, or in a
  window where it was not set. Use the full path shown above.

## Honesty notes for the presentation

- A prediction means "this value resembles known attack payloads", **not** that the request
  succeeded or was genuinely malicious. A security scanner produces the same signals. Scores are
  uncalibrated, not probabilities.
- Only URL query-string values are analysed — not form bodies, headers, or cookies.
- The model was trained on a public dataset, so expect the occasional false positive on unusual
  but legitimate input; mark it on the event page (feedback is stored separately and never
  changes the prediction).
