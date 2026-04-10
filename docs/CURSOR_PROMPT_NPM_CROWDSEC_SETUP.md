# Cursor-Prompt: NPM + CrowdSec Blocking-Page automatisch einrichten

Den **Abschnitt „Prompt für Cursor Agent“** unten in den Chat kopieren (oder als Aufgabe für den Agenten verwenden).

---

## Kontext (für dich)

| Komponente | Rolle |
|------------|--------|
| `error-page` (`npm-error-page`) | Nginx, statische Seite unter `./static` (403-Seite mit `?ip=` & `reason=`) |
| `bouncer` (`npm-crowdsec-bouncer`) | HTTP :8080, prüft CrowdSec LAPI, leitet geblockte Clients per **302** auf `REDIRECT_URL` um |
| Netzwerk | Compose nutzt externes Netz `proxy` |

**Wichtig:** Der Go-Bouncer antwortet bei Ban aktuell mit **302 Redirect**. Nginx-`auth_request` erwartet typischerweise **200** (erlaubt) vs. **401/403** (verweigert), **kein** 302 im Auth-Subrequest. Der Agent soll das erkennen und bei Bedarf `bouncer.go` um einen **dedizierten Endpoint** ergänzen (z. B. nur 200/403), plus passende NPM-**Custom Nginx**-Snippets.

---

## Prompt für Cursor Agent

```
Du richtest die Integration zwischen Nginx Proxy Manager (NPM), dem Repo „npm-proxy-monitor“ (docker-compose) und CrowdSec so ein, dass (1) die Blocking-Page erreichbar ist und (2) geschützte Proxy-Hosts vor dem Upstream gegen die CrowdSec-Entscheidung geprüft werden.

### Ausgangslage (nicht raten, im Workspace verifizieren)

- Lies `docker-compose.yml`: Services `error-page`, `bouncer`, Netzwerk `proxy`, Ports (Bouncer Host z. B. 8503→8080).
- Lies `bouncer.go`: wie Client-IP aus CF-Connecting-IP, True-Client-IP, X-Forwarded-For, X-Real-IP gelesen wird; wie Redirect bei Ban (`REDIRECT_URL`) gebaut wird.
- Lies `static/index.html` / `banned.html`: Query-Parameter `ip`, `reason`.

### Ziel A – Blocking-Page öffentlich

1. Stelle sicher, dass der Hostname aus `REDIRECT_URL` (z. B. blocked.scruzzi.com) per NPM als **Proxy Host** auf den **error-page**-Container zeigt:
   - Forward: `http://<container-name>:80` (im Docker-Netz, in dem NPM den Container sieht).
2. Falls NPM **nicht** im Netz `proxy` hängt: dokumentiere exakt einen der Wege:
   - `docker network connect proxy <npm-container>` (oder gleichwertig), **oder**
   - published Port / Host-URL, die von NPM aus erreichbar ist.
3. SSL (Let’s Encrypt) in NPM wie üblich; Test: `https://<blocked-host>/?ip=1.2.3.4&reason=test` zeigt die 403-Seite mit Text.

### Ziel B – Geschützte Sites: CrowdSec vor dem Upstream

1. Prüfe, ob reines `auth_request` mit dem aktuellen Bouncer möglich ist (302 vs. 200/403).
2. Wenn **nicht** kompatibel: erweitere `bouncer.go` um einen internen Pfad, z. B. `GET /_nginx/auth` oder `GET /auth`:
   - **200** leer = Zugriff erlaubt (CrowdSec: keine Ban-Entscheidung).
   - **403** = Zugriff verweigert (Ban). Optional Header `X-Crowdsec-Reason` setzen.
   - Kein 302 im Auth-Subrequest; Redirect zur Blocking-Page macht der **Hauptrequest** per `error_page 403` oder `return 302` in einem **separaten** `location`, der die `REDIRECT_URL` aus einer env-Map übernimmt – wähle die sauberste nginx-kompatible Variante und setze sie um.
3. Ergänze kurze Doku in README oder `docs/`: NPM **Advanced** / **Custom Nginx** Snippet pro Proxy Host (oder global), das:
   - `auth_request` zum Bouncer-URL (intern) nutzt,
   - Real-IP-Header korrekt weitergibt (Konsistenz mit `bouncer.go`),
   - bei Verweigerung auf die Blocking-Page mit Query-Parametern umleitet (falls nicht schon im Bouncer gelöst).

### Constraints

- Keine unnötigen Refactors außerhalb Bouncer/Doku/ggf. kleinem Compose-Hinweis.
- Bestehende Traefik-/302-Logik für andere Deployments nicht brechen: neuer Endpoint **zusätzlich**, oder per Env-Flag schaltbar.
- Nach Änderungen: `go build` / Tests laufen lassen, die im Repo vorgesehen sind.

### Lieferobjekte

1. Konkrete NPM-Konfigurationsschritte (Screenshots nicht nötig) + Beispiel-Snippets.
2. Code-Änderungen falls nötig (`bouncer.go`, ggf. `docker-compose.yml` nur wenn begründet).
3. Kurze Checkliste zum Testen: erlaubte IP, gebannte IP (CrowdSec Decision), Blocking-Page sichtbar.

Arbeite Schritt für Schritt, committe logisch getrennt (z. B. bouncer-Endpoint, dann Doku).
```

---

## Optional: Kurz-Prompt (nur Blocking-Page)

Wenn du **nur** die statische Seite hinter der Domain brauchst:

```
Richte in Nginx Proxy Manager einen Proxy Host für die Domain aus REDIRECT_URL (siehe docker-compose bouncer) ein: Upstream ist der Container npm-error-page Port 80. NPM muss im Docker-Netz „proxy“ mit error-page erreichen können (docker network connect …). SSL aktivieren. Verifiziere mit https://<domain>/?ip=1.1.1.1&reason=test
```
