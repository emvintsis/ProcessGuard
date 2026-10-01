# ETW Notes — Architecture & Fondamentaux

> Notes d'apprentissage pour le projet ProcessGuard.
> Basé sur la doc Microsoft "About Event Tracing" et "Event Tracing Sessions".

---

## Périmètre du semestre

| Étape | Statut | Ce qu'on fait côté ETW |
|-------|--------|------------------------|
| Création de processus | ✅ Fait | Provider Kernel-Process, PID/PPID/chemin/cmdline via le PEB |
| Chargement de DLL | 🔄 À faire | Même provider (Kernel-Process), keyword image |
| Connexions réseau | 🔄 À faire | Nouveau provider : Microsoft-Windows-Kernel-Network |
| Agent en service Windows | 🔄 À faire | La session ETW est démarrée/arrêtée par le service |
| Moteur de scoring | 🔄 À faire | Les events ETW deviennent l'entrée des règles |

Hors périmètre (suite du projet) : hooks, YARA, Kernel-File, Threat-Intelligence, base de données.

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
              (active les   │      │ (crée la
               providers)   │      │  session)
                            │      │
                  ┌─────────▼─┐  ┌─▼───────────────────────┐
                  │ PROVIDERS │  │     TRACE SESSION        │
                  │           │  │                           │
                  │ Kernel-   │──│──► Buffers (per-CPU)      │
                  │ Process   │  │    Writer thread (flush)  │
                  │           │  │    Config (level, flags)  │
                  │ Kernel-   │──│──►                        │
                  │ Network   │  └─────────┬────────┬───────┘
                  │           │            │        │
                  └───────────┘        Real-time   Fichier
                                           │       .etl
                                 ┌─────────▼────────▼───────┐
                                 │       CONSUMER            │
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

**Une seule session pour plusieurs providers** : pas besoin de créer une session
par provider. On appelle `EnableTraceEx2()` une fois par provider sur la même
session, et tous les events arrivent dans le même callback. C'est ce qu'on fait
pour ajouter Kernel-Network à la session existante.

---

## Les 4 composants en détail

### Provider

- Composant qui **génère** les events (kernel, service, application).
- S'enregistre auprès d'ETW avec un GUID unique.
- Peut être activé/désactivé dynamiquement par un controller.
- Un provider désactivé ne génère pas d'events → zéro overhead quand personne n'écoute.
- Le provider **ne sait pas** qui consomme ses events.

**Pour ProcessGuard** : on ne crée pas de provider. On consomme des providers kernel existants.

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
| `ControlTrace()` | Arrête la session (`EVENT_TRACE_CONTROL_STOP`) ou lit ses stats (`EVENT_TRACE_CONTROL_QUERY`) |

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

### Démarrage (état actuel)

```
1. GetHostInfo() + RegisterAgent()  → le backend renvoie un agent_id
2. ConnectWebSocket()               → canal de commandes (KILL, ...)
3. Allouer EVENT_TRACE_PROPERTIES (+ espace pour le nom de session en WCHAR)
4. Remplir : Wnode.BufferSize, LogFileMode = REAL_TIME, LoggerNameOffset...
5. StartTrace(&tid, L"PGSession", pProperties)
6. EnableTraceEx2(tid, &KernelProcessGUID, ...)
7. Thread 1 : ConsumeEvents → OpenTrace + ProcessTrace (bloquant)
8. Thread 2 : FlushToController → envoi des lots toutes les 5 s
9. Thread 3 : ListenWebSocket → réception des commandes
```

### Démarrage (cible fin de semestre)

```
1. Le SCM démarre le service → ServiceMain()
2. Enregistrer le handler de contrôle (RegisterServiceCtrlHandlerEx)
3. Nettoyer une éventuelle session zombie : ControlTrace(STOP) sur L"PGSession"
4. StartTrace(...)
5. EnableTraceEx2(Kernel-Process, keywords PROCESS | IMAGE)
6. EnableTraceEx2(Kernel-Network, keywords IPV4 | IPV6)
7. Lancer les 3 threads (ETW, flush, WebSocket)
8. SetServiceStatus(SERVICE_RUNNING)
```

### En fonctionnement

```
Un event se produit sur Windows (processus, DLL, connexion)
  → Le kernel (provider) écrit un event dans les buffers de la session
  → Le writer thread flush vers ton consumer
  → Ton callback reçoit un EVENT_RECORD*
  → Tri par ProviderId puis par EventDescriptor.Id
  → Parsing des propriétés (UserData / TDH / PEB selon l'event)
  → TELEMETRY_EVENT écrit dans le buffer circulaire
  → Le thread de flush envoie le lot au backend
  → Le backend applique les règles de scoring
```

### Fermeture

```
Mode console (actuel) :
1. getchar() → l'utilisateur appuie sur Entrée
2. StopETWSession() → ControlTrace(STOP), ProcessTrace retourne
3. Attendre les threads, CloseHandle

Mode service (cible) :
1. Le SCM envoie SERVICE_CONTROL_STOP au handler
2. SetServiceStatus(SERVICE_STOP_PENDING)
3. ControlTrace(STOP) → ProcessTrace retourne dans le thread ETW
4. Signaler un event d'arrêt aux threads flush et WebSocket
5. Attendre les threads, puis SetServiceStatus(SERVICE_STOPPED)
```

---

## GUIDs des providers

| Provider | GUID | Usage |
|----------|------|-------|
| Microsoft-Windows-Kernel-Process | `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` | ✅ Processus (fait) + chargement de DLL (à faire) |
| Microsoft-Windows-Kernel-Network | `{7DD42A49-5329-4832-8DFD-43D979153A88}` | 🔄 Connexions TCP/UDP (à faire ce semestre) |
| Microsoft-Windows-Kernel-File | `{EDD08927-9CC4-4E65-B970-C2560FB5C289}` | Suite du projet — I/O fichiers (accès SAM, SYSTEM hives) |
| Microsoft-Windows-Threat-Intelligence | `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}` | Suite du projet — nécessite PPL, probablement inaccessible |

> Vérifier les GUIDs et les manifests sur la machine avec :
> `logman query providers "Microsoft-Windows-Kernel-Network"`
> `wevtutil gp Microsoft-Windows-Kernel-Process /ge /gm`

---

## Kernel-Process : events et keywords

### Keywords

Aujourd'hui `EnableTraceEx2` est appelé avec `MatchAnyKeyword = 0`, donc on reçoit
tout ce que le provider émet. Pour ajouter les DLL sans être noyé sous les threads,
il vaut mieux passer des keywords explicites :

| Keyword | Valeur | Contenu |
|---------|--------|---------|
| `WINEVENT_KEYWORD_PROCESS` | `0x10` | Start / Stop de processus |
| `WINEVENT_KEYWORD_THREAD` | `0x20` | Start / Stop de threads (bruyant, pas utile pour le moment) |
| `WINEVENT_KEYWORD_IMAGE` | `0x40` | Chargement / déchargement d'images (EXE, DLL) |

→ Pour ce semestre : `MatchAnyKeyword = 0x10 | 0x40`.

### Event IDs

| Event ID | Signification | Statut |
|----------|--------------|--------|
| 1 | Process Start | ✅ Géré |
| 2 | Process Stop | — |
| 3 | Thread Start | — |
| 4 | Thread Stop | — |
| 5 | Image Load | 🔄 À gérer |
| 6 | Image Unload | — |

**À corriger** : le callback actuel teste `Opcode == 1 && Version == 4`. Il est plus
fiable de trier sur `EventHeader.ProviderId` puis `EventHeader.EventDescriptor.Id`,
parce qu'une fois Kernel-Network ajouté, deux providers différents peuvent avoir
des events avec le même opcode.

### Image Load (event 5)

Propriétés utiles : `ProcessID`, `ImageBase`, `ImageSize`, `ImageName`.

- `ImageName` est un chemin au format device (`\Device\HarddiskVolume3\Windows\...`),
  pas `C:\...`. Pour le scoring c'est suffisant (on cherche surtout `\Temp\`,
  `\AppData\`, `\Users\Public\`), la conversion en lettre de lecteur peut attendre.
- Le PID de l'event est celui du processus qui charge la DLL.
- Volume très élevé (chaque processus charge des dizaines de DLL au démarrage).
  → Filtrer dans le callback avant d'écrire dans le buffer circulaire, par exemple
  en ignorant les DLL chargées depuis `\Windows\System32\` au départ.

---

## Kernel-Network : events et keywords

### Keywords

| Keyword | Valeur | Contenu |
|---------|--------|---------|
| `KERNEL_NETWORK_KEYWORD_IPV4` | `0x10` | Trafic IPv4 |
| `KERNEL_NETWORK_KEYWORD_IPV6` | `0x20` | Trafic IPv6 |

### Event IDs utiles

| Event ID | Signification |
|----------|--------------|
| 12 | TCP connect IPv4 |
| 15 | TCP accept IPv4 |
| 28 | TCP connect IPv6 |
| 31 | TCP accept IPv6 |

Les events d'envoi/réception de données (10, 11, 26, 27...) sont **extrêmement bruyants** :
un event par paquet. Pour ce semestre, on ne garde que les connect/accept.

→ Soit on filtre dans le callback sur `EventDescriptor.Id`,
→ soit on passe un filtre `EVENT_FILTER_TYPE_EVENT_ID` dans le paramètre
  `EnableParameters` de `EnableTraceEx2` pour que le kernel ne nous envoie que ces IDs.

Propriétés utiles : `PID`, `daddr`, `saddr`, `dport`, `sport`.

> À vérifier en pratique : l'ordre des octets des ports et adresses (réseau ou hôte).
> Tester avec une connexion connue (ex. `Test-NetConnection 1.1.1.1 -Port 443`).

---

## Parsing des propriétés

| Event | Méthode actuelle / prévue |
|-------|--------------------------|
| Process Start | PID lu directement dans `UserData`, puis `GetProcessInfo()` lit le PEB (PPID, chemin, cmdline) |
| Image Load | TDH (`ExtractProperty`, déjà déclaré dans `processguard.h`) |
| Network connect | TDH |

Lire `UserData` en castant directement marche pour le PID du Process Start parce que
c'est le premier champ, mais pour les autres events la position des champs dépend
de la version de l'event. TDH lit le manifest et donne les propriétés par leur nom,
c'est plus robuste.

**Attention au PEB pour les processus très courts** : si le processus est déjà terminé
quand le callback s'exécute, `OpenProcess` échoue et on a "Unknown". L'event Process
Start contient aussi `ParentProcessID` et `ImageName` : les lire via TDH en secours.

---

## Lien avec le scoring

Les events ETW sont l'entrée du moteur de scoring. Exemples de règles possibles
avec ce qu'on collecte ce semestre :

| Règle | Source | Points (exemple) |
|-------|--------|------------------|
| Office (WINWORD, EXCEL) lance cmd/powershell | Process Start (PPID + nom) | +40 |
| Ligne de commande PowerShell avec `-enc`, `-nop`, `iex`, `downloadstring` | Process Start (cmdline) | +30 |
| LOLBin connu (`certutil -urlcache`, `rundll32` sans DLL système, `mshta`) | Process Start (cmdline) | +25 |
| DLL chargée depuis `\Temp\`, `\AppData\`, `\Users\Public\` | Image Load | +20 |
| Processus non réseau (notepad, calc…) qui ouvre une connexion | Network connect | +30 |
| Connexion sortante d'un processus lancé depuis un dossier temporaire | Network + Process Start | +25 |

Le score est cumulé par PID, une alerte est levée au-delà d'un seuil (ex. 60),
et l'alerte garde la liste des règles qui ont contribué.

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
   → **Encore plus important en mode service**, qui redémarre automatiquement.

4. **Limite 64 sessions** : ne pas créer de sessions en boucle sans les fermer.

5. **Privileges** : les sessions ETW kernel nécessitent des droits administrateur.
   Sans élévation → `ERROR_ACCESS_DENIED` (5). En service sous `LocalSystem`,
   le problème disparaît.

6. **TDH double-call pattern** : `TdhGetEventInformation()` s'appelle d'abord avec
   un buffer NULL pour obtenir la taille requise, puis avec un buffer alloué.
   Même pattern pour beaucoup de fonctions Win32.

7. **Buffer circulaire trop petit** : `BUFFER_SIZE` vaut 100 et le flush passe
   toutes les 5 s. Avec les DLL et le réseau, on dépasse facilement 100 events
   en 5 s, et `head` rattrape `tail` : les events non envoyés sont écrasés sans
   que rien ne le signale. Il faut agrandir le buffer, détecter le débordement
   (compteur d'events perdus) et/ou flusher plus souvent. C'est directement lié
   à l'indicateur de réussite (95 % des events vus par Sysmon).

8. **Callback lent = events perdus** : si le callback fait trop de travail
   (OpenProcess, ReadProcessMemory, TDH…), les buffers de la session se remplissent
   et ETW jette des events. Les stats `EventsLost` de `ControlTrace(QUERY)` permettent
   de le mesurer.

9. **Service et console** : un service n'a pas de console, les `printf` ne
   s'affichent nulle part. Prévoir un fichier de log ou l'Event Log Windows.

---

## Libs à linker

```
advapi32.lib   → StartTrace, EnableTraceEx2, OpenTrace, ProcessTrace, ControlTrace,
                 StartServiceCtrlDispatcher, RegisterServiceCtrlHandlerEx, SetServiceStatus
tdh.lib        → TdhGetEventInformation, TdhGetProperty
winhttp.lib    → transport HTTP + WebSocket
iphlpapi.lib   → GetAdaptersInfo
ws2_32.lib     → InetNtop (conversion des adresses IP des events réseau)
```

---

## Sources

- Microsoft Learn — About Event Tracing :
  https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing

- Microsoft Learn — Event Tracing Sessions :
  https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-sessions

- Microsoft Learn — Configuring and Starting an Event Tracing Session :
  https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session

- Microsoft Learn — EnableTraceEx2 (keywords et filtres) :
  https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2

- Microsoft Learn — The Complete Service Sample (structure d'un service Windows) :
  https://learn.microsoft.com/en-us/windows/win32/services/the-complete-service-sample

- MSDN Magazine — "Event Tracing: Improve Debugging and Performance Tuning with ETW" :
  https://learn.microsoft.com/en-us/archive/msdn-magazine/2007/april/event-tracing-improve-debugging-and-performance-tuning-with-etw

- Windows Internals Part 1, 7th Ed. — Russinovich, Solomon, Ionescu
