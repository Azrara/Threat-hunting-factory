# Evidence samples

Ready made evidence for trying a hypothesis without collecting real logs. Upload a file here
directly in the hunt wizard, or zip it first if you prefer.

| File | Hypothesis | Data source |
|------|------------|-------------|
| `sysmon-privilege-escalation.json` | Privilege escalation has been attempted on hosts in scope | Sysmon operational log |

## sysmon-privilege-escalation.json

495 Sysmon records covering the record types the data source calls for: process creation with
command lines and hashes (event 1), network connections (3), driver and image loads (6 and 7),
registry changes (13) and DNS queries (22). Ordinary activity across five workstations, with one
escalation chain planted on `WS-FIN-014`:

1. User Account Control bypass staged in `Software\Classes\ms-settings\Shell\Open\command` with
   `DelegateExecute`, triggered through the auto elevating `fodhelper.exe`, and a second attempt
   through `computerdefaults.exe`.
2. A vulnerable driver brought along and loaded, from `sc create` to the kernel load of an unsigned
   `RTCore64.sys`.
3. Exploitation of a named vulnerability against the print spooler.
4. The gained privilege persisted into the local administrators group.
5. The elevated payload resolving and reaching its controller.

Running it against the privilege escalation hypothesis produces:

```
495 records, risk 66.8 out of 100, high, credible attack activity
12 observations from 9 detections
  critical  mal-vulnerable-driver-load
  high      mal-exploit-attempt-generic
  high      win-remote-admin-account-created
  high      win-uac-bypass
  medium    stat-rare-lineage, once for each step of the chain
```

The remaining detections in that hypothesis cover Linux, containers and the cloud control plane.
They stay silent here because the evidence is Windows only, which is the correct result rather than
a gap.

Regenerate with `python tools/generate_privilege_escalation_sample.py`. The generator is seeded, so
it reproduces this file exactly.
