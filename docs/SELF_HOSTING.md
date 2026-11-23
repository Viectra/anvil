# Guide d'Auto-Hébergement & Exploitation — **Anvil**

> **Version de référence** : `v1.0.0`  
> **Sécurité & modèle de menaces** : [`SECURITY.md`](./SECURITY.md) · **Architecture** : [`ARCHITECTURE.md`](./ARCHITECTURE.md)

Ce guide couvre le déploiement sécurisé d'`anvil-server` en production avec **PostgreSQL 16** ou **SQLite**, via **Docker Compose** ou en installation **Linux systemd**, ainsi que la configuration du reverse proxy TLS, l'administration CLI et les sauvegardes.

---

## 1. Prérequis & Génération des Secrets d'Instance

Anvil exige deux secrets cryptographiques persistants (`ANVIL_JWT_PRIVATE_KEY` et `ANVIL_PRELOGIN_SECRET`) et recommande fortement un poivre serveur (`ANVIL_AUTH_PEPPER`). La perte de `ANVIL_AUTH_PEPPER` invalide les connexions existantes ; conservez donc votre fichier `.env` dans une sauvegarde chiffrée hors ligne.

```bash
cp deploy/.env.example deploy/.env
chmod 600 deploy/.env
cargo run --release -p anvil-server -- keygen
```

Copiez les valeurs affichées dans `deploy/.env` ainsi qu'un mot de passe robuste pour `POSTGRES_PASSWORD`. Ne commitez jamais `deploy/.env`.

### Variables d'environnement principales

| Variable | Défaut | Description |
| --- | --- | --- |
| `ANVIL_DATABASE_URL` | — *(requis)* | Chaîne PostgreSQL (`postgres://...`) ou SQLite (`sqlite:///data/anvil.db`). |
| `ANVIL_BIND_ADDR` | `127.0.0.1:8080` | Adresse d'écoute TCP (`0.0.0.0:8080` dans les conteneurs Docker). |
| `ANVIL_ALLOW_SIGNUPS` | `false` | Autorise ou bloque les inscriptions publiques sans jeton d'invitation. |
| `ANVIL_JWT_PRIVATE_KEY` | — *(requis)* | Clé privée Ed25519 (PEM ou DER base64) signant les JWT d'accès (15 min). |
| `ANVIL_PRELOGIN_SECRET` | — *(requis)* | Clé secrète HMAC générant des sels factices anti-énumération sur `/prelogin`. |
| `ANVIL_AUTH_PEPPER` | vide *(recommandé)* | Secret serveur appliqué lors du re-hachage `Argon2id` des authentifications. |
| `ANVIL_TRUSTED_PROXIES` | vide | Plages CIDR autorisées à transmettre `X-Forwarded-For` au limiteur de débit. |
| `ANVIL_CORS_ORIGINS` | vide | Origines autorisées (ex. ID d'extension navigateur ou origine web contrôlée). |
| `ANVIL_ENABLE_FAVICON_PROXY` | `false` | Active le proxy de favicons (protégé SSRF) sur `/api/v1/favicon/{domain}`. |
| `ANVIL_PUBLIC_URL` | vide | URL HTTPS publique de l'instance. |
| `ANVIL_LOG_FORMAT` | `pretty` | `pretty` en développement, `json` en production et conteneur Docker. |

---

## 2. Déploiement Docker Compose (Recommandé)

Le fichier [`deploy/docker-compose.yml`](../deploy/docker-compose.yml) s'appuie sur [`deploy/Dockerfile`](../deploy/Dockerfile) (image finale `gcr.io/distroless/cc-debian12:nonroot`, utilisateur `65532:65532`) et applique :

- Système de fichiers racine en lecture seule (`read_only: true`) avec `/tmp` en `tmpfs` (`noexec,nosuid,size=16m`)
- Suppression de toutes les capacités Linux (`cap_drop: [ALL]`) et `no-new-privileges:true`
- Limitation des ressources (`pids_limit`, `mem_limit`) et désactivation des *core dumps* (`ulimits: core: 0`)
- Exposition liée uniquement à `127.0.0.1:${ANVIL_PORT:-8080}:8080` pour imposer un reverse proxy TLS frontal

### Option A — PostgreSQL 16 (production multi-utilisateurs)

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.yml --env-file deploy/.env ps
```

### Option B — SQLite autonome (mono-instance / faible empreinte)

```bash
docker compose -f deploy/docker-compose.yml --env-file deploy/.env --profile sqlite up -d --build
```

Vérifiez la disponibilité locale avant d'ouvrir le reverse proxy :

```bash
curl -fsS http://127.0.0.1:8080/api/v1/health
```

---

## 3. Déploiement Bare-Metal Linux (`systemd`)

Pour exécuter `anvil-server` directement sur un hôte Linux :

1. Compilez ou installez le binaire vers `/usr/local/bin/anvil-server` (`chmod 755`).
2. Créez l'utilisateur système et les répertoires isolés :
   ```bash
   sudo useradd --system --home /var/lib/anvil --shell /usr/sbin/nologin anvil
   sudo install -d -o anvil -g anvil -m 0700 /var/lib/anvil
   sudo install -d -o root -g anvil -m 0750 /etc/anvil
   ```
3. Placez votre configuration dans `/etc/anvil/anvil.env` (`chmod 0640`, propriétaire `root:anvil`).
4. Copiez [`deploy/anvil-server.service.example`](../deploy/anvil-server.service.example) vers `/etc/systemd/system/anvil-server.service`, puis activez le service :
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now anvil-server
   sudo systemctl status anvil-server
   ```

Le binaire embarque sa propre commande de sonde sans dépendance à `curl` :

```bash
/usr/local/bin/anvil-server healthcheck --url http://127.0.0.1:8080/api/v1/health
```

---

## 4. Reverse Proxy TLS & En-têtes d'Origine

N'exposez jamais `anvil-server` en HTTP brut sur Internet : terminez **TLS 1.3** devant `127.0.0.1:8080` à l'aide des modèles fournis :

- **Caddy** : [`deploy/Caddyfile.example`](../deploy/Caddyfile.example)
- **Traefik** : [`deploy/traefik.example.yml`](../deploy/traefik.example.yml)

Points d'attention critiques :

1. **`ANVIL_TRUSTED_PROXIES`** : ne listez que les plages IP ou CIDR exactes de votre reverse proxy (`127.0.0.1/32` sur le même hôte, ou le sous-réseau bridge Docker). Anvil remonte la chaîne `X-Forwarded-For` de droite à gauche et ignore toute IP non précédée d'un proxy de confiance.
2. **`ANVIL_CORS_ORIGINS`** : laissez vide si vous n'utilisez que les clients natifs ou configurez explicitement les origines navigateur autorisées si votre déploiement y accède depuis un contexte cross-origin.
3. **`ANVIL_ENABLE_FAVICON_PROXY`** : maintenez à `false` si vous ne souhaitez pas que le serveur effectue de requêtes HTTPS sortantes vers les domaines enregistrés dans les coffres.

---

## 5. Administration CLI (`anvil-server`)

Toutes les tâches d'administration s'exécutent via le binaire `anvil-server` (directement ou avec `docker compose exec anvil /usr/local/bin/anvil-server ...`) :

```bash
# Appliquer manuellement les migrations SQL en attente
anvil-server migrate

# Créer une invitation à usage unique valable 72 h
anvil-server invite create --email alice@example.com --max-uses 1 --expires-hours 72

# Lister et révoquer des invitations
anvil-server invite list
anvil-server invite revoke <INVITATION_UUID>

# Gestion des utilisateurs (identifiant : email ou UUID)
anvil-server user list
anvil-server user promote alice@example.com
anvil-server user demote alice@example.com
anvil-server user disable alice@example.com
anvil-server user enable alice@example.com
```

> Les options `serve --no-migrate` permettent d'empêcher l'application automatique des migrations au démarrage lorsqu'un pipeline dédié exécute `anvil-server migrate` en amont.

---

## 6. Sauvegardes & Restauration

Conservez systématiquement **deux éléments** ensemble : un instantané cohérent de la base de données **et** une copie chiffrée de `deploy/.env` (contenant `ANVIL_AUTH_PEPPER`, `ANVIL_PRELOGIN_SECRET` et `ANVIL_JWT_PRIVATE_KEY`).

### PostgreSQL 16

```bash
# Sauvegarde cohérente au format personnalisé
docker compose -f deploy/docker-compose.yml exec -T postgres \
  pg_dump -U anvil -Fc anvil > anvil-$(date +%F).dump

# Restauration dans une base saine
docker compose -f deploy/docker-compose.yml stop anvil
cat anvil-YYYY-MM-DD.dump | docker compose -f deploy/docker-compose.yml exec -T postgres \
  pg_restore -U anvil -d anvil --clean --if-exists
docker compose -f deploy/docker-compose.yml start anvil
```

### SQLite (mode WAL)

Ne copiez jamais un fichier `.db` actif avec un simple `cp` tant que des journaux `-wal` sont ouverts : arrêtez le service ou utilisez la commande de sauvegarde transactionnelle en ligne `sqlite3 .backup` / `VACUUM INTO` :

```bash
sqlite3 /var/lib/anvil/anvil.db ".backup '/var/backups/anvil/anvil-$(date +%F).db'"
```

En complément des sauvegardes serveur, les utilisateurs peuvent exporter à tout moment une archive chiffrée autonome `.anvil` depuis **Anvil Desktop**.

---

## 7. Procédure de Mise à Jour

1. Vérifiez les notes de version et réalisez une sauvegarde complète PostgreSQL ou SQLite + `.env`.
2. Récupérez le tag souhaité (ex. `v1.0.0`) ou reconstruisez le conteneur :
   ```bash
   git fetch --tags
   git checkout v1.0.0
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env build
   ```
3. Redémarrez le service (`anvil-server` applique automatiquement les migrations SQL manquantes au lancement, sauf avec `--no-migrate`) :
   ```bash
   docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d
   ```
4. Contrôlez `/api/v1/health` et les journaux JSON (`docker compose -f deploy/docker-compose.yml logs -n 50 anvil`).
