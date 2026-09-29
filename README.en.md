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

![Connection, summary and lists](/en/01-connection-summary-lists.png)

### 2. Threshold selection, double confirmation and deletion result

![Selection, double confirmation and deletion](/en/02-selection-double-confirmation-deletion.png)

### 3. If the second confirmation does not match, the operation is cancelled

![Second confirmation cancelled](/en/03-second-confirmation-cancelled.png)

### 4. If "N" is given at the first confirmation, the operation is cancelled

![First confirmation cancelled](/en/04-first-confirmation-cancelled.png)

### 5. If there are no stale agents, the deletion question is not asked

![No stale agents](/en/05-no-stale-agents.png)

---

Author: FIRAT AYDIN
