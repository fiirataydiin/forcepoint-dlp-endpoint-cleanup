[Türkçe](README.md) | **English**

# Forcepoint DLP - Endpoint Status Cleanup

`ForcepointAgentCleanup.en.ps1` lists agent records that have not reported for a long time in the Forcepoint Security Manager (FSM) console **Status > Endpoint Status** list, and deletes them with a double confirmation.

## What it does

1. Connects to SQL Server (`sqlcmd.exe`, Windows or SQL Server authentication).
2. Shows the total number of agents in the system.
3. Counts agents that have not reported for **7 / 15 / 30 days** and lists them with Hostname, IP, Last Update, Sync, user and version.
4. Asks how old the records to delete must be.
5. Requires a **double confirmation**: first Y/N, then typing the number of records to delete.
6. Backs up the records to be deleted as a CSV on the desktop, deletes them in a single transaction and reports the number of deleted agents.

The "not reporting" duration is calculated from `PA_DYNAMIC_STATUS.UPDATE_DATE` (**Last Update** in the FSM console).

## Scope and safety

- Rows are deleted from only two tables, and **only for the agents shown on screen and confirmed**:
  - `PA_DYNAMIC_STATUS_PROPS` (agent status properties)
  - `PA_DYNAMIC_STATUS` (Endpoint Status row)
- Incident, policy, user and all other tables are never touched. No `DROP`, `TRUNCATE`, `UPDATE` or `ALTER` is used.
- If either confirmation is not given, nothing is deleted.
- Agents that reconnect between listing and deletion are not deleted.
- Records without a Last Update value are never included in deletion.
- On error, the transaction is rolled back.
- This does **not** uninstall the agent from the machine. If the agent connects again, its record is recreated.

## Usage

```powershell
.\ForcepointAgentCleanup.en.ps1
```

```powershell
.\ForcepointAgentCleanup.en.ps1 -SqlServerInstance "SQL01" -SqlAuthMode SqlLogin -SqlUserName sa
```

| Parameter | Default | Description |
|---|---|---|
| `-SqlServerInstance` | (prompted) | SQL Server name, e.g. `SERVER` or `SERVER\INSTANCE` |
| `-SqlDatabaseName` | `wbsn-data-security` | Forcepoint DLP database |
| `-SqlAuthMode` | (prompted) | `Windows` or `SqlLogin` |
| `-SqlUserName` | (prompted) | SQL Login username; the password is prompted securely |

Requirements: Windows PowerShell 5.1+, `sqlcmd.exe` in PATH, read/delete permission on the related tables in the database.

## Screenshots

> The screenshots are from a test run with sample agent data. Hostnames, IPs and usernames are not real.

### 1. Connection, summary and stale agent lists

![Connection, summary and lists](docs/images/en/01-connection-summary-lists.png)

### 2. Threshold selection, double confirmation and deletion result

![Selection, double confirmation and deletion](docs/images/en/02-selection-double-confirmation-deletion.png)

### 3. If the second confirmation does not match, the operation is cancelled

![Second confirmation cancelled](docs/images/en/03-second-confirmation-cancelled.png)

### 4. If "N" is given at the first confirmation, the operation is cancelled

![First confirmation cancelled](docs/images/en/04-first-confirmation-cancelled.png)

### 5. If there are no stale agents, the deletion question is not asked

![No stale agents](docs/images/en/05-no-stale-agents.png)

## Version 2: delete a specific machine by hostname

`ForcepointAgentCleanup_v2.en.ps1` has everything in v1 and can also delete specific machine(s) by hostname. The v1 script is unchanged, so both versions can be used side by side.

```powershell
.\ForcepointAgentCleanup_v2.en.ps1
```

A new option was added to the deletion menu:

```text
  4 = Delete specific machine(s) by hostname
```

- Enter one or more hostnames separated by commas, e.g. `PC-FIN-014, LT-IT-007`.
- Hostnames must match **exactly** (case-insensitive). Wildcards such as `*`, `?` and `%` are not accepted.
- Hostnames not found in the list are reported.
- A warning is shown for machines that still look active (connected within the last 7 days). Even if deleted, they come back to the list on their next connection.
- Double confirmation, CSV backup and the single transaction still apply. The backup is saved as `Forcepoint_EndpointStatus_Deleted_Selected_....csv`.
- Machines whose Last Update changed between listing and deletion (reconnected) are not deleted.
- The menu is shown even when there are no agents older than 7 days, so deleting by hostname is always available.

### 1. Delete by hostname (with a not-found hostname and an active machine warning)

![Delete by hostname](docs/images/en/v2/01-delete-by-hostname.png)

### 2. Wildcards are rejected

![Wildcard rejected](docs/images/en/v2/02-wildcard-rejected.png)

### 3. Delete by hostname when there are no stale agents

![No stale agents, delete by hostname](docs/images/en/v2/03-no-stale-agents-delete-by-hostname.png)

---

Author: FIRAT AYDIN
