# PHP2Shell detection rules

Detections for **CVE-2026-109618** and **CVE-2026-109619** ("PHP2Shell"), a pair of
critical unauthenticated remote code execution flaws in PHP, reported as exploited in
the wild from 21 October 2026. Both affect PHP serving web requests across PHP-FPM,
mod_php, php-cgi, FrankenPHP and LiteSpeed.

| Rule | Type | Detects | ATT&CK |
|------|------|---------|--------|
| `sigma/php_worker_spawns_shell.yml` | Sigma | A PHP worker spawning a shell or downloader (post-exploitation) | T1059.004, T1505.003 |
| `sigma/php2shell_upload_progress_abuse.yml` | Sigma | Reported exploitation indicators in the multipart request | T1190 |
| `yara/php_webshell_generic.yar` | YARA | PHP web shells dropped on disk after RCE | T1505.003 |

## Detection strategy

The three rules sit at different points on the kill chain deliberately. The request
rule catches delivery but depends on the exploit's current shape; the process-lineage
rule catches what the attacker does next and survives a change of exploit; the YARA
rule catches the artefact left behind. Layering them means a change in any one
technique does not blind the detection as a whole.

Patching is the control. These rules are for finding what got in first.

## Testing

- Sigma: `sigma convert -t splunk --without-pipeline sigma/`
- YARA: `yara yara/php_webshell_generic.yar tests/` — matches `webshell_sample.txt`, not `benign_sample.txt`

The fixtures in `tests/` are inert. The web shell patterns sit inside quoted string
literals after an `exit()`, and the files carry a `.txt` extension, so nothing can
execute. YARA scans content rather than extension, so the rule still matches. Some
antivirus products may still flag files containing these patterns.

## References

- [watchTowr — PHP2Shell RCE exploited](https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/)
- [Akamai — Understanding PHP2Shell](https://www.akamai.com/blog/security-research/understanding-php2shell-everything-you-need-to-know)
