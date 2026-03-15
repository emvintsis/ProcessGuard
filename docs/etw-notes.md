# ETW Notes — Architecture & Fondamentaux

> Notes d'apprentissage pour le projet ProcessGuard.
> Basé sur la doc Microsoft "About Event Tracing" et "Event Tracing Sessions".

---

## Modèle architectural

ETW fonctionne sur un modèle **publish-subscribe** avec 4 composants :

```
                    ┌──────────────────────┐
                    │      CONTROLLER      │
                    │  (ton programme)     │
                    │                      │
                    │  StartTrace()        │
                    │  EnableTraceEx2()    │
                    │  ControlTrace()      │
                    └───────┬──────┬───────┘
                            │      │
              EnableTraceEx2│      │ StartTrace
              (active le    │      │ (crée la
               provider)    │      │  session)
                            │      │
                  ┌─────────▼─┐  ┌─▼───────────────────────┐
                  │ PROVIDER  │  │     TRACE SESSION        │
                  │           │  │                           │
                  │ Kernel-   │──│──► Buffers (per-CPU)      │
                  │ Process   │  │    Writer thread (flush)  │
                  │           │  │    Config (level, flags)  │
                  │ GUID:     │  │                           │
                  │ {22FB2CD6 │  └─────────┬────────┬───────┘
                  │  -0E7B-   │            │        │
                  │  422B-    │        Real-time   Fichier
                  │  A0C7-    │            │       .etl
                  │  2FAD1FD0 │            │        │
                  │  E716}    │  ┌─────────▼────────▼───────┐
                  └───────────┘  │       CONSUMER            │
                                 │  (ton programme aussi)    │
                                 │                           │
                                 │  OpenTrace()              │
                                 │  ProcessTrace() ← bloquant│
                                 │  CloseTrace()             │
                                 │                           │
                                 │  Callback reçoit un       │
                                 │  EVENT_RECORD par event   │
                                 └───────────────────────────┘
```

**Point clé** : dans ProcessGuard, ton programme joue à la fois le rôle de
Controller ET de Consumer. C'est un usage normal et documenté par Microsoft.

---

## Les 4 composants en détail

### Provider

- Composant qui **génère** les events (kernel, service, application).
- S'enregistre auprès d'ETW avec un GUID unique.
- Peut être activé/désactivé dynamiquement par un controller.
- Un provider désactivé ne génère pas d'events → zéro overhead quand personne n'écoute.
- Le provider **ne sait pas** qui consomme ses events.

**Pour ProcessGuard** : on ne crée pas de provider. On consomme un provider kernel existant.

**Types de providers** :

| Type | API d'écriture | Sessions max | Notes |
|------|---------------|-------------|-------|
| MOF (classic) | RegisterTraceGuids + TraceEvent | 1 | Legacy |
| WPP | RegisterTraceGuids + TraceEvent | 1 | Debug, TMF files |
| **Manifest-based** | EventRegister + EventWrite | **8** | **Le type moderne, celui qu'on utilise** |
| TraceLogging | TraceLoggingRegister + TraceLoggingWrite | 8 | Self-describing events |

### Controller

- **Orchestre** les sessions et les providers.
- Crée/démarre/arrête les trace sessions.
- Active les providers sur une session donnée.
- Accède aux statistiques de la session (buffers utilisés, events perdus...).

**Fonctions du controller** :

| Fonction | Rôle |
|----------|------|
| `StartTrace()` | Crée et démarre une nouvelle trace session |
| `EnableTraceEx2()` | Active un provider sur la session (lui dit d'envoyer ses events) |
| `ControlTrace()` | Arrête la session (avec `EVENT_TRACE_CONTROL_STOP`) |

### Trace Session

- **Canal de communication** entre providers et consumers.
- Vit dans le kernel.
- Possède des **buffers per-CPU** (pas de lock → haute performance).
- Un **writer thread** dédié flush les buffers vers le consumer ou un fichier.
- Deux modes de livraison : **real-time** (direct au consumer) ou **fichier .etl**.
- Limite système : **64 sessions simultanées max** (certaines déjà utilisées par Windows).
- Identifiée par un **nom** (string) et un **TRACEHANDLE** (retourné par StartTrace).

**Attention** : une session non fermée reste active même si ton programme crashe.
→ Toujours nettoyer avec `ControlTrace(STOP)`.
→ Si une session zombie existe, `StartTrace` retourne `ERROR_ALREADY_EXISTS` (183).

### Consumer

- Application qui **lit** les events d'une ou plusieurs sessions.
- Peut lire en **real-time** ou depuis un **fichier .etl**.
- Les events arrivent dans l'**ordre chronologique**, même depuis plusieurs sessions.
- Reçoit chaque event sous forme d'un `EVENT_RECORD*` dans un callback.

**Fonctions du consumer** :

| Fonction | Rôle |
|----------|------|
| `OpenTrace()` | S'abonne à une session, fournit le callback |
| `ProcessTrace()` | Démarre la boucle de réception (**BLOQUANT** → thread dédié) |
| `CloseTrace()` | Ferme la connexion au consumer |

---

## Flux complet dans ProcessGuard

### Démarrage

```
1. Allouer EVENT_TRACE_PROPERTIES (+ espace pour le nom de session en WCHAR)
2. Remplir : Wnode.BufferSize, LogFileMode = REAL_TIME, LoggerNameOffset...
3. StartTrace(&hSession, L"ProcessGuardSession", pProperties)
4. EnableTraceEx2(hSession, &KernelProcessGUID, EVENT_CONTROL_CODE_ENABLE_PROVIDER, ...)
5. Remplir EVENT_TRACE_LOGFILE avec le nom de session + pointeur vers le callback
6. OpenTrace(&traceLogfile) → hTrace
7. CreateThread(...) qui appelle ProcessTrace(&hTrace, 1, NULL, NULL)
```

### En fonctionnement

```
Un processus démarre sur Windows
  → Le kernel (provider) écrit un event dans les buffers de la session
  → Le writer thread flush vers ton consumer
  → Ton callback reçoit un EVENT_RECORD*
  → Tu parses avec TDH : PID, PPID, ImageFileName, CommandLine
  → Tu affiches / analyses
```

### Fermeture (handler Ctrl+C)

```
1. CloseTrace(hTrace)         ← côté consumer
2. WaitForSingleObject(hThread, INFINITE)  ← attendre que ProcessTrace retourne
3. ControlTrace(hSession, NULL, pProperties, EVENT_TRACE_CONTROL_STOP) ← côté controller
```

---

## GUIDs des providers pertinents

| Provider | GUID | Usage |
|----------|------|-------|
| Microsoft-Windows-Kernel-Process | `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` | **Phase 1** — Création/destruction de processus et threads |
| Microsoft-Windows-Kernel-File | `{EDD08927-9CC4-4E65-B970-C2560FB5C289}` | Phase 3 — I/O fichiers (accès SAM, SYSTEM hives) |
| Microsoft-Windows-Threat-Intelligence | `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}` | Phase 3 — Mitigations (nécessite PPL, probablement inaccessible) |

---

## Opcodes du provider Kernel-Process

| Opcode | Signification |
|--------|--------------|
| 1 | Process Start |
| 2 | Process Stop |
| 3 | Thread Start |
| 4 | Thread Stop |

Accessible via `EventHeader.EventDescriptor.Opcode` dans le `EVENT_RECORD`.

---

## Pièges à retenir

1. **EVENT_TRACE_PROPERTIES sizing** : la taille allouée doit inclure la structure
   + l'espace pour le nom de session en WCHAR qui suit immédiatement en mémoire.
   Sinon StartTrace échoue silencieusement ou corrompt la mémoire.

2. **ProcessTrace est bloquant** : il faut le lancer dans un thread dédié avec
   `CreateThread()`, sinon le programme entier est figé.

3. **Session zombie** : si le programme crashe sans appeler `ControlTrace(STOP)`,
   la session reste active. Au prochain lancement, `StartTrace` retourne
   `ERROR_ALREADY_EXISTS` (183). Solution : tenter un `ControlTrace(STOP)` avec
   le même nom de session avant `StartTrace`.

4. **Limite 64 sessions** : ne pas créer de sessions en boucle sans les fermer.

5. **Privileges** : les sessions ETW kernel nécessitent des droits administrateur.
   Sans élévation → `ERROR_ACCESS_DENIED` (5).

6. **TDH double-call pattern** : `TdhGetEventInformation()` s'appelle d'abord avec
   un buffer NULL pour obtenir la taille requise, puis avec un buffer alloué.
   Même pattern pour beaucoup de fonctions Win32.

---

## Libs à linker

```
advapi32.lib   → StartTrace, EnableTraceEx2, OpenTrace, ProcessTrace, ControlTrace
tdh.lib        → TdhGetEventInformation, TdhGetProperty
psapi.lib      → EnumProcesses, GetModuleFileNameEx (Phase 2)
ntdll.lib      → NtQuerySystemInformation (Phase 3, ou chargement dynamique)
```

---

## Sources

- Microsoft Learn — About Event Tracing :
  https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing

- Microsoft Learn — Event Tracing Sessions :
  https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-sessions

- Microsoft Learn — Configuring and Starting an Event Tracing Session :
  https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session

- MSDN Magazine — "Event Tracing: Improve Debugging and Performance Tuning with ETW" :
  https://learn.microsoft.com/en-us/archive/msdn-magazine/2007/april/event-tracing-improve-debugging-and-performance-tuning-with-etw

- Windows Internals Part 1, 7th Ed. — Russinovich, Solomon, Ionescu