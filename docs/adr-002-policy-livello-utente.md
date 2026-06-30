
# ADR-002 — Applicazione delle policy Chrome a livello utente (HKCU)

> Documento di design / Architecture Decision Record.
> **Stato:** Proposto · **Data:** 2026-06-30 · **Autore:** @robgrame (con GitHub Copilot)
> **Ambito:** estendere Chrome Policy Manager per applicare policy Chrome **per-utente**
> (hive `HKCU`), oggi limitato alle policy **macchina** (`HKLM`), introducendo un secondo
> asse di targeting (Machine/User) e la risoluzione delle assegnazioni sui **gruppi
> dell'utente loggato**.
>
> Documento complementare a [`adr-001-decoupling-azioni-privilegiate.md`](./adr-001-decoupling-azioni-privilegiate.md),
> [`chrome-browser-cloud-management.md`](./chrome-browser-cloud-management.md) e
> [`chromium-policy-loading.md`](./chromium-policy-loading.md).

---

## 1. Contesto

Lo stato attuale della soluzione applica le policy Chrome **solo a livello macchina**:

| Componente | Comportamento attuale |
|---|---|
| `Models/PolicyAssignment.cs` | `enum PolicyScope { Mandatory, Recommended }` — entrambi mappati su **HKLM** |
| `Services/EffectivePolicyService.cs` | risolve l'effective policy **per device** (`GetDeviceGroupMembershipsAsync(deviceId)`) |
| `Client/Detect-ChromePolicy.ps1` / `Remediate-ChromePolicy.ps1` | `#Requires -RunAsAdministrator`, eseguono come **SYSTEM**; scrivono `HKLM:\SOFTWARE\Policies\Google\Chrome` e `...\Recommended` |
| Manifest / compliance | per-device in `HKLM:\SOFTWARE\ChromePolicyManager` |

### 1.1 Il problema: manca un asse, non un valore

`Mandatory` vs `Recommended` è il **livello di enforcement**, non il target. Chrome legge
le policy da registro su **quattro destinazioni** che derivano da **due assi ortogonali**:

| | Mandatory | Recommended |
|---|---|---|
| **Machine** | `HKLM\SOFTWARE\Policies\Google\Chrome` | `HKLM\SOFTWARE\Policies\Google\Chrome\Recommended` |
| **User** | `HKCU\SOFTWARE\Policies\Google\Chrome` | `HKCU\SOFTWARE\Policies\Google\Chrome\Recommended` |

Oggi modelliamo solo la **riga Machine**. "User-based" **non** è `Recommended`: è un
**secondo asse di targeting** (`Machine` / `User`) che si combina con lo scope esistente.

### 1.2 Perché serve

- Policy che hanno senso **per persona** e non per device (es. impostazioni legate al
  profilo/identità dell'utente, configurazioni differenziate per ruolo su device condivisi).
- Device **multi-utente** (postazioni condivise, VDI/AVD): la stessa macchina deve poter
  ricevere set di policy diversi a seconda di **chi è loggato**.
- Allineamento al modello classico GPO "Computer Configuration" vs "User Configuration".

---

## 2. Decisione

Introdurre un **secondo asse di targeting** `PolicyTarget { Machine, User }` ortogonale a
`PolicyScope { Mandatory, Recommended }`, e una **pipeline di applicazione in contesto
utente** orchestrata dallo script SYSTEM tramite uno **scheduled task** che gira come
utente loggato.

Le assegnazioni con `Target = User` vengono risolte sui **gruppi dell'utente** (Graph
`transitiveMemberOf` dell'utente), non sui gruppi del device. La scrittura avviene in `HKCU`
nel profilo dell'utente reale.

> **Stato di implementazione:** questo ADR è **design-only**. Nessuna modifica al codice è
> inclusa; la sezione §10 elenca i workstream proposti.

---

## 3. Modello dati

### 3.1 Nuovo asse `PolicyTarget`

```csharp
public enum PolicyTarget
{
    Machine = 0,  // HKLM\SOFTWARE\Policies\Google\Chrome[\Recommended]
    User    = 1   // HKCU\SOFTWARE\Policies\Google\Chrome[\Recommended]
}
```

Aggiunto a `PolicyAssignment` accanto a `Scope`:

```csharp
public PolicyTarget Target { get; set; } = PolicyTarget.Machine; // default = comportamento odierno
```

La combinazione `(Target, Scope)` determina **una delle 4 destinazioni di registro**. La
priorità (`Priority`, lower-wins) resta valida **dentro ogni bucket**; la precedenza
**fra** bucket è gestita da Chrome (vedi §6).

### 3.2 Semantica del gruppo assegnato

- `Target = Machine` → il gruppo Entra è interpretato come **gruppo di device**; risoluzione
  via `GetDeviceGroupMembershipsAsync(deviceId)` (invariato).
- `Target = User` → il gruppo Entra è interpretato come **gruppo di utenti**; risoluzione via
  i gruppi dell'**utente loggato** (nuovo, §5).

La UI dovrà rendere esplicita questa semantica (badge "Machine"/"User") e validare/avvisare
quando il tipo di gruppo selezionato non corrisponde al target.

### 3.3 Compatibilità

`Target` ha default `Machine`: tutte le assegnazioni esistenti mantengono il comportamento
attuale. Migrazione EF additiva (colonna non-null con default 0), nessun breaking change sul
contratto effective-policy se i nuovi bucket sono opzionali (§4).

---

## 4. API: effective policy a 4 bucket

### 4.1 Endpoint dedicato e versioning

**Decisione:** endpoint utente **dedicato** e contratto **versionato a `/v2`**, separato da
quello device. Due chiamate indipendenti, due ETag indipendenti:

| Verbo | Endpoint | Bucket restituiti | Hash |
|---|---|---|---|
| `GET` | `/api/v2/devices/{id}/effective-policy` | `machineMandatory`, `machineRecommended` | `machineHash` |
| `GET` | `/api/v2/users/{upn}/effective-policy` | `userMandatory`, `userRecommended` | `userHash` |

Esempio risposta dell'endpoint **utente**:

```jsonc
{
  "upn": "mario.rossi@contoso.com",
  "userMandatory":   { ... },
  "userRecommended": { ... },
  "userHash": "...",            // ETag dedicato → If-None-Match per-utente
  "appliedAssignments": [ ... ]
}
```

> **Retro-compatibilità:** gli endpoint v1 esistenti (`/api/devices/{id}/effective-policy`,
> campi `mandatoryPolicies`/`recommendedPolicies`) restano invariati per gli script v13. Il
> nuovo comportamento a 4 destinazioni vive interamente sotto **`/api/v2/...`**; lo script
> aggiornato passa a v2 sia per il bucket machine sia per quello user.

### 4.2 Identità utente e risoluzione

L'`upn` è nel **path** dell'endpoint utente (`/api/v2/users/{upn}/effective-policy`). La
**risoluzione dei gruppi avviene server-side via Graph** (trusted), come per i device: il
client non auto-dichiara mai le proprie membership. La correlazione "utente realmente loggato
sul device" è descritta in §8.

### 4.3 Risoluzione lato server

Nuovo metodo su `IGraphService`:

```csharp
Task<IReadOnlyList<string>> GetUserGroupMembershipsAsync(string userId); // transitiveMemberOf / getMemberGroups
```

`EffectivePolicyService` estende la query assegnazioni filtrando per `Target`:

- bucket **machine**: assignment con `Target = Machine` ∧ gruppo ∈ gruppi-device;
- bucket **user**: assignment con `Target = User` ∧ gruppo ∈ gruppi-utente.

Il merge first-writer-wins per `Priority` resta invariato **dentro** ciascun bucket.

---

## 5. Applicazione in contesto utente (orchestrazione)

### 5.1 Vincolo di base

Lo script Intune (detection/remediation) gira come **SYSTEM**. Scrivere `HKCU` da SYSTEM
colpisce il profilo di SYSTEM, **non** quello dell'utente. `HKCU\SOFTWARE\Policies` è invece
**scrivibile dall'utente stesso senza privilegi elevati**.

### 5.2 Approccio scelto — scheduled task in contesto utente (lanciato da SYSTEM)

Pattern proposto (conferma utente): lo script SYSTEM **crea ed esegue un scheduled task
transitorio** che gira come **utente loggato**, poi raccoglie l'esito e lo elimina. Il task
viene eseguito per **tutti gli utenti interattivi loggati**; la selezione di *quali* policy
applicare è demandata al server in base alla membership del gruppo (vedi §5.2.1).

```
[Remediation SYSTEM]
   │  1. Enumera le sessioni interattive attive
   │     (Win32_Process explorer.exe → GetOwner → SID + UPN, oppure 'query user')
   │  2. Per OGNI utente loggato:
   │       Register-ScheduledTask  (Principal: <DOMAIN\user>, LogonType=Interactive)
   │         Action: powershell -File Apply-UserChromePolicy.ps1
   │       Start-ScheduledTask  → poll fino a completamento
   │       Leggi esito (exit code / file risultato in %LOCALAPPDATA% o HKCU manifest)
   │       Unregister-ScheduledTask
   ▼
[Task in contesto USER]
   │  a. Ricava l'identità utente nativamente (token già dell'utente):
   │       whoami /upn · WindowsIdentity · Entra objectId · dsregcmd /status
   │  b. GET /api/v2/users/{upn}/effective-policy  (mTLS device cert per il trasporto)
   │       → se l'utente NON è in alcun gruppo assegnato: bucket vuoti, nessuna scrittura
   │  c. Scrive HKCU\SOFTWARE\Policies\Google\Chrome[\Recommended]
   │  d. Scrive manifest per-utente in HKCU\SOFTWARE\ChromePolicyManager
   │  e. Rimuove le chiavi HKCU stantie (Remove-StaleKeys per-utente, §7)
   │  f. (opz.) Report compliance per (device, utente) all'API
   ▼
[Remediation SYSTEM] aggrega gli esiti → exit 0/1 verso Intune
```

#### 5.2.1 Regola di applicazione (multi-utente)

**Decisione:** il task user gira **sempre** in contesto utente per **ogni** utente loggato.
È il **server** a decidere: l'endpoint `/api/v2/users/{upn}/effective-policy` ritorna le policy
**solo se** quell'utente appartiene a un gruppo con assegnazioni `Target = User`. Se l'utente
**non** è membro di alcun gruppo assegnato, i bucket sono **vuoti** e **nessuna policy** viene
scritta (e le eventuali chiavi HKCU pregresse vengono rimosse come stantie). Questo copre
nativamente i device **multi-sessione** (VDI/AVD/RDS): ogni sessione riceve il proprio set.

**Pro**
- Un'unica Remediation Intune (SYSTEM); nessuna seconda assegnazione "run as logged-on user".
- Identità utente **affidabile** (token nativo del task), `HKCU` scrivibile senza elevazione.
- Profilo utente corretto anche con **più utenti** loggati (un task per sessione).

**Contro / rischi da mitigare**
- Complessità di **lifecycle** del task (creazione, attesa, cleanup, idempotenza).
- **AV/EDR** possono segnalare scheduled task transitori creati da SYSTEM.
- **Cattura dell'output** cross-contesto: SYSTEM legge l'esito dal profilo utente
  (path `%LOCALAPPDATA%` o `HKEY_USERS\<SID>`).
- **Timing**: nessun utente loggato → solo policy machine; sessione che termina durante l'esecuzione.

### 5.3 Alternativa scartata (per ora) — `HKEY_USERS\<SID>` da SYSTEM

SYSTEM scrive direttamente in `HKEY_USERS\<SID>\SOFTWARE\Policies\Google\Chrome`, caricando
`NTUSER.DAT` se l'hive non è montato. Evita lo scheduled task ma:
- gestione manuale del **load/unload** dell'hive per utenti non attivi (rischio corruzione/lock);
- ottenere l'**UPN/objectId** dell'utente da SID richiede comunque una risoluzione;
- più fragile su VDI/profili roaming/FSLogix.

### 5.4 Alternativa — Remediation Intune nativa in contesto utente

Seconda Remediation con "Run this script using the logged-on credentials". Più pulita
concettualmente, ma raddoppia le assegnazioni e la telemetria, e disaccoppia detection
machine e user. Tenuta come opzione B.

---

## 6. Precedenza delle policy in Chrome

Da documentare per gli amministratori (evita conflitti non intuitivi):

- **Mandatory batte sempre Recommended**, indipendentemente dall'hive.
- A parità di chiave **mandatory**, la policy **macchina (HKLM) ha precedenza su utente (HKCU)**
  (salvo override espliciti come `CloudPolicyOverridesPlatformPolicy`, non in scope qui).
- La `Priority` di CPM (lower-wins) opera **solo all'interno dello stesso bucket**; la
  precedenza **fra** machine e user è decisa da Chrome, non da CPM.

**Raccomandazione UI/UX:** segnalare quando la **stessa chiave** è impostata sia in un
assignment `Machine` sia in uno `User` con lo stesso scope (la versione machine vincerà),
così l'admin non si aspetta che la user-policy "vinca".

---

## 7. Reporting & stato

- **Manifest per-utente**: `HKCU\SOFTWARE\ChromePolicyManager\Manifest` (chiavi gestite,
  hash applicato), gestito dal task user. Il manifest machine resta in `HKLM`.
- **Compliance per (device, utente)**: il report attuale è per-device. Per l'utente serve
  estendere il modello (`UserPolicyState` o dimensione `userId` sul report) e l'API di
  ingestion. La dashboard dovrà poter mostrare lo stato user accanto a quello machine.
- **Hash separati** (machine/user) per ETag/`If-None-Match` indipendenti → invariata
  l'efficienza di scaling descritta nel README.

---

## 8. Sicurezza

- **Trust dell'identità utente — correlazione via `dsregcmd`.** L'`upn` nel path è asserito dal
  contesto del task (gira come quell'utente), ma per evitare che un client richieda la policy di
  **un altro utente** adottiamo una **correlazione "utente realmente loggato sul device"**:
  - Il task user esegue **`dsregcmd /status`** e ne estrae lo stato SSO/PRT dell'utente sul
    device Entra-joined (sezione *SSO State* / *User State*: presenza di **PRT**, `AzureAdPrt = YES`,
    e l'identità Entra associata). Questo dimostra che l'utente è **genuinamente autenticato a
    Entra su quel device**, non un UPN arbitrario.
  - Il binding (deviceId Entra da `dsregcmd` + UPN/objectId utente) viene incluso nella richiesta;
    il server **valida la coerenza** device↔utente e **logga** chi richiede quale UPN da quale
    device. Una richiesta il cui UPN non è corroborato dal PRT del device viene **rifiutata/loggata**.
  - In opzione (fase 2) si può rafforzare con la correlazione lato Entra dei **sign-in** recenti.
- **mTLS invariato**: il trasporto resta autenticato dal **client certificate device** emesso
  dalla **PKI del cliente** (vedi README §Security). L'identità utente è un *claim applicativo*,
  non sostituisce l'auth di trasporto.
- **Nessun privilegio aggiuntivo** richiesto sul device: `HKCU\SOFTWARE\Policies` è scrivibile
  dall'utente; lo scheduled task usa il token utente esistente.
- **Graph**: `GetUserGroupMembershipsAsync` richiede `User.Read.All`/`GroupMember.Read.All`
  (application). Coerente con il modello MI già in uso; nessuna app-role privilegiata nuova.

---

## 9. Impatti sui componenti

| Componente | Modifica prevista |
|---|---|
| `Models/PolicyAssignment.cs` | + `enum PolicyTarget`, + proprietà `Target` (default Machine) |
| `Data/AppDbContext.cs` + migration | colonna `Target` additiva |
| `Services/IGraphService.cs` / `GraphService.cs` | + `GetUserGroupMembershipsAsync(userId)` |
| `Services/EffectivePolicyService.cs` | risoluzione a 4 bucket per `Target`; hash machine/user |
| **nuovo** `Endpoints/UserEndpoints.cs` (v2) | `GET /api/v2/users/{upn}/effective-policy`; ETag/`userHash`; validazione binding `dsregcmd` |
| `Endpoints/DeviceEndpoints.cs` (v2) | variante `/api/v2/devices/{id}/effective-policy` con bucket machine + `machineHash` |
| `Endpoints/AssignmentEndpoints.cs` + DTO Admin | `Target` in create/update; UI badge + validazione |
| `Client/Detect-ChromePolicy.ps1` / `Remediate-ChromePolicy.ps1` | orchestrazione scheduled task user; aggregazione esiti |
| **nuovo** `Client/Apply-UserChromePolicy.ps1` | child in contesto utente: fetch user-policy, scrive HKCU, manifest, report |
| Reporting model / Dashboard | stato compliance per (device, utente) |

---

## 10. Workstream proposti (per quando si passa all'implementazione)

| # | Workstream | Esito |
|---|---|---|
| 1 | Modello dati: `PolicyTarget` + migration + default Machine | ⏳ |
| 2 | API: `GetUserGroupMembershipsAsync` + endpoint `/api/v2/users/{upn}/effective-policy` + `/api/v2/devices/...` (bucket machine) + ETag separati | ⏳ |
| 3 | Admin UI: selettore `Target`, badge, validazione tipo-gruppo, avviso conflitti chiave | ⏳ |
| 4 | Client: `Apply-UserChromePolicy.ps1` (contesto utente) + `Remove-StaleKeys` per-utente + binding `dsregcmd` | ⏳ |
| 5 | Client: orchestrazione scheduled task da SYSTEM + aggregazione esiti | ⏳ |
| 6 | Reporting per (device, utente) + dashboard | ⏳ |
| 7 | Documentazione admin: precedenza machine/user, best practice no-overlap | ⏳ |

---

## 11. Decisioni risolte

Le domande aperte sono state risolte (2026-06-30):

1. **Multi-sessione** → applicare a **tutti gli utenti loggati** che appartengono al gruppo di
   assegnazione. Lo scheduled task gira **sempre** in contesto utente per ogni sessione; se
   l'utente **non** appartiene ad alcun gruppo assegnato, **nessuna policy** viene applicata
   (bucket vuoti + rimozione chiavi HKCU stantie). Vedi §5.2.1.
2. **Endpoint** → **dedicato**: `GET /api/v2/users/{upn}/effective-policy` (separato dal device).
   Vedi §4.1.
3. **Anti-spoofing userId** → **correlazione "utente realmente loggato sul device"** ottenuta
   tramite **`dsregcmd /status`** (PRT/SSO state Entra) e validata/loggata lato server. Vedi §8.
4. **Pulizia** → alla disassegnazione di una user-policy o al logoff, **rimozione delle chiavi
   HKCU stantie** con la **stessa semantica di `Remove-StaleKeys`** già usata per HKLM, applicata
   per-utente. Vedi §5.2 e §7.
5. **Versioning contratto** → **`/v2`** dedicato; gli endpoint/campi v1 restano invariati per gli
   script v13. Vedi §4.1.

---

*Fine ADR-002.*
