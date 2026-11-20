# Audit overview

2 repositories. Each row links to the full report of that run.

> **Scope note.** This audit checks technical controls and collects evidence. It does not establish legal compliance with the GDPR, the EU AI Act, the Cyber Resilience Act or any other regulation. Whether a regulation applies, and whether it is met, must be decided by a responsible person and, where needed, legal counsel. A missing finding never means the software is free of defects.

| Repository | Commit | Scope | PASS | FAIL | UNKNOWN | N/A | critical | high | medium | low | confirmed | Problems |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [full](report.md) | `7351cb69d4c9` | full | 8 | 38 | 2 | 2 | 3 | 11 | 18 | 14 | 9 | 0 |
| [change](change/report.md) | `c173101b4384` | change since `main` (1 file) | 12 | 7 | 0 | 31 | 1 | 2 | 3 | 2 | 3 | 0 |

## Critical and high findings

- **critical** (confirmed) change: Change removes owner check: any logged-in user can read any message – `app/api/messages.py:35-37`
- **critical** (tool_reported) full: SQL injection in /search via the q parameter – `app/api/search.py:13-18`
- **critical** (confirmed) full: Any logged-in user can read any message by ID – `app/api/messages.py:35-42`
- **critical** (confirmed) full: Prompt injection from incoming e-mail can make the assistant send mail – `app/assistant.py:36-43`
- **high** (confirmed) change: GET /messages/{id} marks any user's message as read (owner filter removed) – `app/api/messages.py:36-41`
- **high** (confirmed) change: Change removes owner restriction when reading a message, exposing other users' mail – `app/api/messages.py:36-37`
- **high** (confirmed) full: Restore ignores the saved previous folder and read state – `app/api/messages.py:62-64`
- **high** (tool_reported) full: IMAP sync swallows fetch/parse errors and marks the message as seen – `app/sync.py:25-31`
- **high** (confirmed) full: Sync marks messages \Seen upstream before the local commit, so a re-run after failure cannot recover them – `app/sync.py:30-32`
- **high** (confirmed) full: JWT secret defaults to an empty string with no startup validation – `app/config.py:4-4`
- **high** (confirmed) full: Account deletion leaves attachment files on disk – `app/api/account.py:13-17`
- **high** (confirmed) full: Message read endpoint does not restrict access to the owner – `app/api/messages.py:35-42`
- **high** (tool_reported) full: JWT signing secret committed to Git history – `app/config.py:4`
- **high** (tool_reported) full: SMTP password baked into the image via build arg and ENV – `Dockerfile:2-3`
- **high** (tool_reported) full: Path traversal in attachment download – `app/api/attachments.py:13-21`
- **high** (confirmed) full: JWT signing key defaults to an empty string – `app/config.py:4-5`
- **high** (confirmed) full: send_mail tool runs without user confirmation or recipient limits – `app/assistant.py:44-48`

