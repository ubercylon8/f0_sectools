# Safe LCQL starter queries (LimaCharlie)

LCQL shape: `time | sensor-selector | event-types | filter | projection`

- **time**: `-24h`, `-1h`, or an explicit range.
- **sensor-selector**: `*` (all), `plat == windows`, `hostname contains "web"`.
- **event-types**: `NEW_PROCESS`, `DNS_REQUEST`, `NETWORK_CONNECTIONS`,
  `NEW_DOCUMENT`, `MODULE_LOAD`, or `*`.
- **filter**: `event/FIELD contains "..."`, comparisons, or `*` for none.
- **projection**: fields to return, or `*`.

All are read-only. Adjust the selector/filter, keep the window tight, and pass to
`query_telemetry` (which also takes `hours_back` / `limit` bounds).

## Suspicious process execution (e.g. LOLBins, PowerShell download cradles)

```
-24h | plat == windows | NEW_PROCESS | event/FILE_PATH contains "powershell" | event/FILE_PATH event/COMMAND_LINE
```

## Process ancestry — office app spawning a shell

```
-24h | plat == windows | NEW_PROCESS | event/PARENT/FILE_PATH contains "winword" | event/FILE_PATH event/COMMAND_LINE
```

## DNS lookups to a domain of interest

```
-24h | * | DNS_REQUEST | event/DOMAIN_NAME contains "example" | event/DOMAIN_NAME
```

## Outbound network connections

```
-1h | plat == windows | NETWORK_CONNECTIONS | * | event/NETWORK_ACTIVITY
```

## Scope a hunt to one host

```
-24h | hostname == "web-01" | NEW_PROCESS | * | event/FILE_PATH event/COMMAND_LINE
```

## Discovery — see recent events of any type on a host

```
-1h | hostname == "web-01" | * | * | routing/event_type
```
