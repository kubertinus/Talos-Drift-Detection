# Talos Drift Detection

Webapp die de actuele machineconfig van elke Talos-node vergelijkt met de originele
`controlplane.yaml` / `worker.yaml` en de configuratie-drift per node overzichtelijk toont,
gescheiden in **controlplanes** en **workers**, voor **meerdere clusters** tegelijk.

- Overzicht met de status van alle clusters: in orde / drift / fout, met per node een gekleurd blokje
- Per cluster een eigen basismap, bestanden, patches, ignore-regels en scaninterval

- Node-discovery via `talosctl get members` (of een handmatige nodelijst)
- Per node: status *in sync* / *drift* / *onbereikbaar*, aantal afwijkingen, sinds wanneer
- Detailpagina met tabel van afwijkende paden en side-by-side YAML-diff
- "Wijkt af van meerderheid": nodes van dezelfde rol die anders driften dan de rest
- Patches (strategic merge, JSON6902, multi-document) per cluster, rol of node opnemen in de baseline
- Ignore-regels voor paden die per node legitiem verschillen (hostname, interfaces, install disk, …)
- Periodieke scan (standaard elke 15 min) en een knop "Nu scannen"

## Beveiliging

- Geüploade bestanden (talosconfig, baselines, patches), instellingen en scanresultaten worden
  **Fernet-versleuteld** (AES-128-CBC + HMAC-SHA256) op het volume `/data` opgeslagen. De sleutel
  wordt via HKDF afgeleid van `MASTER_KEY`.
- Na upload zijn deze bestanden niet meer in te zien of te downloaden; de UI toont alleen een
  SHA-256-fingerprint.
- Een geüploade talosconfig bestaat alleen tijdens een scan als plaintext, als 0600-bestand op een
  tmpfs (`/tmp`). Gekoppelde bestanden blijven op de host staan (read-only mount); de app kopieert
  ze niet.
- Secrets in configs (tokens, CA-keys, encryptiesecrets, alles wat op `key`/`token`/`secret`
  eindigt) worden vóór vergelijken vervangen door `***sha256:xxxxxxxx`. Je ziet dus dát een
  secret afwijkt, niet de waarde.
- Web-UI achter een admin-wachtwoord en/of Keycloak (OpenID Connect), sessiecookie `HttpOnly` +
  `SameSite=Lax`, CSRF-tokens, rate-limit op inlogpogingen.
- Alleen bereikbaar via HTTPS (TLS 1.2+); HTTP stuurt door. Bij de eerste start wordt een
  self-signed certificaat gemaakt, daarna kies je Let's Encrypt of een eigen certificaat.
- Container draait als non-root, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`.
- Minimaal image zonder bekende CVE's: Chainguard/Wolfi-Python zonder shell of package manager,
  talosctl en lego uit broncode gebouwd met de nieuwste Go (zie *Image en CVE's*).

> **Rechten:** de machineconfig is een *sensitive* resource in Talos. Een talosconfig met alleen
> `os:reader` kan die niet lezen; de app heeft een talosconfig met `os:admin` nodig. Beperk daarom
> de netwerktoegang tot de app (bijv. alleen intern of achter een reverse proxy met TLS).

## Starten

```bash
# 1. Secrets aanmaken (worden als Docker secrets gemount)
python3 -c "import secrets; print(secrets.token_urlsafe(48))" > secrets/master_key
printf '%s' 'kies-een-sterk-wachtwoord' > secrets/admin_password
chmod 600 secrets/*

# 2. (optioneel) .env voor overige instellingen
cp .env.example .env

# 3. Bouwen en starten (haalt automatisch de nieuwste talosctl op)
docker compose up -d --build
```

Open https://localhost (of de `HTTPS_PORT` uit `.env`), accepteer eenmalig het self-signed
certificaat, log in en voeg onder **Instellingen → Nieuw cluster** een cluster toe. Kies in de
instellingen van dat cluster de basismap, de talosconfig, `controlplane.yaml`, `worker.yaml` en
eventuele patches. Herhaal dit voor elk cluster. **Alles scannen** op het overzicht scant alle
clusters; op een clusterpagina scant **Nu scannen** alleen dat cluster.

Data van een eerdere versie (één cluster) wordt bij de eerste start automatisch omgezet naar een
cluster, vernoemd naar de basismap.

### Bestanden kiezen of uploaden

Staan je Talos-bestanden op dezelfde machine als Docker, zet dan in `.env`:

```bash
CONFIG_HOST_DIR=/Users/jij   # bijv. je home-map
```

Die map wordt read-only op `/configs` gemount. Onder **Instellingen → Basismap** kies je met een
mappenkiezer de map van je cluster (mappen met een talosconfig of controlplane.yaml zijn gemarkeerd),
en daaruit kies je de bestanden en patches. Verwijzingen worden relatief aan de basismap opgeslagen:
wissel je naar een ander cluster met dezelfde indeling (`_out/…`, `patch/…`), dan blijven ze werken.

De app leest gekoppelde bestanden bij elke scan opnieuw, dus wijzigingen op de host worden
automatisch meegenomen. Verborgen bestanden en mappen (`.ssh`, `.talos`, …) worden nooit getoond of
gelezen, en paden buiten de basismap (`..`, symlinks) worden geweigerd.

Zonder gekoppelde map, of als alternatief, kun je de bestanden uploaden; die worden dan versleuteld
in het volume opgeslagen.

**Bewaar `secrets/master_key` goed**: zonder deze sleutel is de data in het volume onleesbaar
(dan opnieuw uploaden).

### Instellingen (env)

| Variabele | Standaard | Omschrijving |
|---|---|---|
| `MASTER_KEY` / `MASTER_KEY_FILE` | – | Encryptiesleutel, min. 32 tekens (verplicht) |
| `ADMIN_PASSWORD` / `ADMIN_PASSWORD_FILE` | – | Wachtwoord voor de web-UI (optioneel als OIDC aan staat) |
| `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | – | Inloggen via Keycloak/OIDC, zie hieronder |
| `SESSION_SECRET` | afgeleid van `MASTER_KEY` | Sleutel voor sessiecookies |
| `COOKIE_SECURE` | `true` | Alleen relevant met `TLS_ENABLED=false` zonder HTTPS-proxy |
| `HTTPS_PORT` / `HTTP_PORT` | `443` / `80` | Host-poorten voor HTTPS en de doorverwijzing |
| `TLS_HOSTNAMES` | – | Extra namen in het eerste self-signed certificaat |
| `TLS_ENABLED` | `true` | `false` achter een TLS-terminerende reverse proxy |
| `CONFIG_HOST_DIR` | `./configs` | Host-map die read-only op `/configs` wordt gemount; de basismap kies je daarbinnen in de UI |
| `TALOSCTL_VERSION` | `latest` | talosctl in de image; `latest` = nieuwste stabiele release, of een tag zoals `v1.11.5` om vast te pinnen |
| `SCAN_INTERVAL` | `900` | Standaard scaninterval in seconden voor nieuwe clusters (per cluster aan te passen) |
| `SCAN_CONCURRENCY` | `5` | Aantal nodes dat tegelijk gescand wordt |
| `NODE_TIMEOUT` | `30` | Timeout per talosctl-aanroep in seconden |

### Image: architecturen en tag

Het image wordt altijd gebouwd voor **linux/amd64** en **linux/arm64** (`build.platforms` in
`docker-compose.yml`); talosctl en lego worden per architectuur gekozen. Naam en tag stel je in
met `IMAGE_NAME` en `IMAGE_TAG` in `.env` (standaard `talos-drift:latest`).

Je lokale Docker moet beide varianten kunnen opslaan (containerd image store). Op Docker Desktop
gebruik je daarvoor de eigen builder: zet `BUILDX_BUILDER=desktop-linux` in `.env`. Een
docker-container-builder bewaart lokaal maar één architectuur. Controleren:
`docker image ls --tree talos-drift:latest`.

Naar een registry pushen, bijv. die van Gitea:

```bash
docker login git.example.com
IMAGE_NAME=git.example.com/team/talos-drift IMAGE_TAG=1.0.0 docker compose build --push
```

### Image en CVE's

Het runtime-image is `cgr.dev/chainguard/python:latest` (Wolfi): alleen Python en de libraries
die het nodig heeft, geen shell, geen package manager, geen pip. Het OS-deel en de
Python-pakketten hebben daardoor geen bekende CVE's.

talosctl en lego zijn de officiële releasebinaries, geverifieerd tegen de checksums van de release.
Bij elke build wordt de nieuwste stabiele release gekozen uit de GitHub-releasefeeds, die ook als
cache-sleutel dienen (vast zetten kan met `TALOSCTL_VERSION` / `LEGO_VERSION`). Scanners melden in
die binaries soms CVE's in de meegebakken Go-standaardbibliotheek; die verdwijnen zodra Sidero
of lego een release met een nieuwere Go uitbrengt, dus regelmatig opnieuw bouwen helpt.

Alle bouwstappen draaien op het bouwplatform in Debian-images (`python:3.15-slim`): de
Python-wheels voor de doelarchitectuur worden gedownload in plaats van onder emulatie
geïnstalleerd, dus QEMU is niet nodig en een volledige build duurt seconden. PyYAML draait als
pure Python. De pakketten moeten bij dezelfde Python-minorversie horen als het runtime-image; een
controlestap laat de build falen als Chainguard naar een nieuwe versie gaat (pas dan
`PYTHON_VERSION` aan, bijv. `--build-arg PYTHON_VERSION=3.16`).

Controleren: `trivy image --platform linux/amd64 talos-drift:latest`.

De web-UI laadt niets van internet: Tailwind, Alpine.js en diff2html zitten (vaste versies) in
`app/static/vendor/`. De app werkt dus ook op een systeem zonder internetverbinding; alleen
Let's Encrypt heeft dan uiteraard geen zin.

## HTTPS en certificaten

De app is alleen via HTTPS bereikbaar. In de container luistert HTTPS op 8443 en HTTP op 8080;
HTTP stuurt alles door naar HTTPS (behalve `/healthz` en Let's Encrypt-challenges). Op de host
kies je de poorten met `HTTPS_PORT` (standaard 443) en `HTTP_PORT` (standaard 80).

Bij de eerste start maakt de app een **self-signed** certificaat voor `localhost`, `127.0.0.1` en
de namen in `TLS_HOSTNAMES`. Onder **Instellingen → HTTPS-certificaat** vervang je dat door:

- **Let's Encrypt** (via [lego](https://go-acme.github.io/lego/), dat in de image zit):
  - *HTTP-01*: de domeinnaam moet publiek naar deze machine wijzen en poort 80 moet vanaf
    internet bereikbaar zijn (`HTTP_PORT=80`).
  - *DNS-01*: een TXT-record via de API van je DNS-provider (Cloudflare, TransIP, Route 53,
    Hetzner, … ruim 150 providers). Werkt ook voor interne servers en wildcards. De pagina toont
    welke variabelen de provider nodig heeft.
  - Gebruik eerst de staging-omgeving om rate limits te voorkomen. Vernieuwen gaat automatisch.
- **Een eigen certificaat** met private key, intermediates en root (los of in één bestand, in
  willekeurige volgorde; een versleutelde key met wachtwoordzin kan ook). De app zet de keten op
  volgorde, controleert handtekeningen en geldigheid, en stuurt leaf + intermediates mee.
- **Een nieuw self-signed certificaat**, bijv. met de hostnaam waarmee je de app opent.

Een nieuw certificaat is direct actief, zonder herstart. Certificaat, key en het
Let's Encrypt-account worden versleuteld opgeslagen. HSTS wordt alleen meegestuurd bij een
vertrouwd certificaat op een echte hostnaam (niet bij self-signed, `localhost` of een IP).

Termineert een reverse proxy al TLS, zet dan `TLS_ENABLED=false`; de app serveert dan gewoon
HTTP op poort 8080.

## Inloggen met Keycloak (OpenID Connect)

Naast (of in plaats van) het admin-wachtwoord kun je inloggen via Keycloak of een andere
OIDC-provider. Maak in Keycloak een client aan:

| Instelling | Waarde |
|---|---|
| Client type | OpenID Connect, *Client authentication* aan (confidential) |
| Standard flow | aan |
| Valid redirect URIs | `https://<app>/auth/callback` |
| Valid post logout redirect URIs | `https://<app>/login` |

Maak een realm- of clientrol aan (bijv. `talos-drift`) en ken die toe aan de gebruikers of
groepen die toegang mogen hebben. Zet daarna in `.env`:

```bash
OIDC_ISSUER=https://sso.example.com/realms/infra
OIDC_CLIENT_ID=talos-drift
OIDC_CLIENT_SECRET=...           # of OIDC_CLIENT_SECRET_FILE
OIDC_ALLOWED_ROLES=talos-drift   # aanbevolen; zonder rol/groep mag iedereen uit de realm erin
```

Het inlogscherm toont dan **Inloggen met Keycloak**. Laat je `ADMIN_PASSWORD` weg, dan is dat de
enige manier om in te loggen. Toegang beperken kan op rollen (`OIDC_ALLOWED_ROLES`: realm-rollen en
clientrollen van deze client) en/of groepen (`OIDC_ALLOWED_GROUPS`: de `groups`-claim, waarvoor in
Keycloak een *Group Membership*-mapper nodig is). Uitloggen beëindigt ook de Keycloak-sessie.

De app en de browser moeten de Keycloak-URL allebei kunnen bereiken. Draait de app achter een
reverse proxy, zorg dan dat die `X-Forwarded-Proto`/`Host` doorgeeft, of zet `OIDC_REDIRECT_URI`.

## Hoe drift bepaald wordt

1. Per node: `talosctl -n <node> get machineconfig v1alpha1 -o yaml` levert de actieve config
   (ook multi-document configs, zoals `HostnameConfig` of `ExtensionServiceConfig`).
2. De rol komt uit `machine.type`; controlplanes worden vergeleken met `controlplane.yaml`,
   workers met `worker.yaml`.
3. Op die baseline worden de toepasselijke patches gezet (zie hieronder).
4. Beide kanten worden gemaskeerd, ignore-paden worden weggefilterd, en daarna volgt een
   recursieve vergelijking (`added` / `removed` / `changed`). Lege waarden (`null`, `{}`, `[]`)
   tellen als afwezig.

### Patches

Patches die je bewust op het cluster hebt toegepast (bijv. met `--config-patch`,
`--config-patch-control-plane` of per node via `talosctl apply-config`/`patch mc`) kies je uit de
gekoppelde map (of upload je) onder **Instellingen → Patches**, met per patch een doel:

| Doel | Toegepast op |
|---|---|
| Alle nodes | elke node |
| Controlplanes / Workers | alle nodes van die rol |
| Specifieke node | één node, op hostname of IP |

De patches worden met `talosctl machineconfig patch` op de baseline gezet, dus precies zoals Talos
dat zelf doet. Volgorde: eerst "alle nodes", dan de rol, dan node-specifiek; binnen een groep van
boven naar beneden (met de pijltjes aan te passen). Bij upload wordt de patch alvast op de baseline
getest. Een patch die niet (meer) past geeft een rode status *patchfout* op de betrokken nodes.
Patches worden net als de rest versleuteld opgeslagen.

Een patch die wél in de baseline staat maar niet op de node is toegepast, verschijnt als drift.

Afwijkingen worden per veld gerapporteerd, ook als er een heel document of blok bij is gekomen.
Zo kun je precies negeren wat per node mag verschillen en blijft de rest bewaakt.

Ignore-regels gebruiken punt-notatie, lijstindexen als `[0]` en documenten als `Kind` of
`Kind[naam]`. Een regel negeert ook alles eronder. Wildcards:

| Patroon | Matcht |
|---|---|
| `[*]` | elke lijstindex of documentnaam, bijv. `LinkConfig[*].addresses` |
| `*` | één segment, bijv. `machine.kubelet.extraArgs.*` |
| `**` | alles, ook over meerdere segmenten |

Standaard worden alleen hostname, IP-adressen per interface en de install disk genegeerd.
Op de detailpagina zet je een afwijking met "negeren" op de lijst (het voorstel is aan te passen),
en onder "Genegeerd" zie je welke afwijkingen door welke regel worden weggefilterd.

Tip: patches die je per node bewust toepast (bijv. via `talosctl gen config --config-patch`)
kun je het beste in de baseline opnemen of als ignore-pad toevoegen.

## Ontwikkelen

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/pytest
MASTER_KEY=$(python3 -c "print('x'*40)") ADMIN_PASSWORD=dev COOKIE_SECURE=false \
  DATA_DIR=./data TMP_DIR=./data/tmp .venv/bin/uvicorn app.main:app --reload
```
