
# Advent of Cyber Writeups Repository

Welcome to the Advent of Cyber 2025 Writeups!

This repository is dedicated to documenting solutions, lessons, and experiences from the TryHackMe Advent of Cyber event and other CTF challenges. Each challenge will have its own folder and writeup, making it easy to track progress and share knowledge.

## Event Introduction

Get ready for the Advent of Cyber 2025! This year’s event features daily beginner-friendly cybersecurity challenges, festive storylines, and a massive prize draw. Join the fun, learn new skills, and help save Wareville from King Malhare!

**Prizes:** Over $150,000 in tech gear, subscriptions, certifications, and more. The more rooms you complete, the higher your chances of winning!

**How to Qualify:** Complete rooms in the Advent of Cyber 2025 event by December 31, 2025. Each completed room earns you raffle tickets for the prize draw.

**Certificate:** Complete every room to earn a certificate of completion with your name.

## General Rules

- Only hack machines deployed in the rooms you have access to.
- Do not attack other users or the TryHackMe infrastructure.
- No cheating, bot accounts, or puppet accounts.
- Answers should not be shared except in official videos/streams.

For full terms and conditions, see the official TryHackMe event page.

## Repository Purpose & Structure

This repository holds writeups for each challenge. Structure your contributions as follows:

### Recommended Folder Structure

- `THM-Writeups/`
  - `1. Challenge Name/`
    - `WRITEUP.md`
    - `notes.txt`
    - `exploit.py`
    - `screenshots/`

### How to Add a New Challenge
1. Create a new directory with a numbered prefix and short name, e.g. `02. Web - SQLi`.
2. Add a `WRITEUP.md` covering: objective, steps taken, commands used, screenshots, final flag(s), and lessons learned.
3. Keep sensitive data out of the repo (passwords, private keys). If needed, redact or store securely.

## Commit & Push (Suggested)

Use the following commands in PowerShell from the `THM-Writeups` directory:

```powershell
# ensure branch name (rename if needed)
git branch -M main
# stage README and new challenge folders
git add README.md "1. Linux CLI - Shells Bells"
# commit
git commit -m "Add main README and initial Day 1 writeup"
# add remote if not added
git remote add origin https://github.com/umair-aziz025/THM-Advent-of-Cyber
# push
git push -u origin main
```

## Notes
- Add a `.gitignore` to exclude virtual environments, OS files, and editor backups (e.g., `venv/`, `*.pyc`, `.vscode/`).
- If multiple people contribute, follow a branch-per-feature workflow and open PRs.

## Contact
Maintainer: `Mr. Umair` — open an issue or PR for changes to this template.
