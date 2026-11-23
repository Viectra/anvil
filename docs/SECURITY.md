# Sécurité & Modèle de Menaces — **Anvil**

> **Version de référence** : `v1.0.0`  
> **Architecture technique** : [`ARCHITECTURE.md`](./ARCHITECTURE.md) · **Guide d'exploitation** : [`SELF_HOSTING.md`](./SELF_HOSTING.md)

Ce document décrit les garanties cryptographiques Zero-Knowledge d'Anvil, le durcissement mémoire et système des clients comme du serveur, le modèle de menaces retenu, les limites connues et les procédures d'intervention en cas de compromission d'un appareil.

---

## 1. Architecture Cryptographique Zero-Knowledge

Toutes les opérations de chiffrement, de déchiffrement et de dérivation de clés sensibles s'exécutent exclusivement côté client dans `anvil-core` (natif et WebAssembly via `anvil-wasm`). Le serveur `anvil-server` ne reçoit jamais ni le *Master Password*, ni la *MasterEncryptionKey*, ni la *VaultKey* en clair.

| Primitive | Paramètres Anvil v1.0 | Rôle |
| --- | --- | --- |
| **KDF client** | `Argon2id` (`64 MiB` / `65 536 KiB`, `t = 3`, `p = 1`) | Dérive un `MasterSecret` de 32 octets à partir du *Master Password* et d'un sel aléatoire de 32 octets par utilisateur. |
| **Séparation de domaine** | `HKDF-SHA256` | Dérive indépendamment `MasterEncryptionKey` (jamais transmise au serveur) et `MasterAuthHash` (transmise uniquement via TLS pour l'authentification). |
| **Chiffrement authentifié** | `XChaCha20-Poly1305` (nonce CSPRNG 192 bits) | Protège la `VaultKey` (256 bits aléatoires), chaque `VaultItem`, chaque `VaultFolder`, chaque logo/blob chiffré et le cache SQLite local. |
| **Enveloppe binaire** | Version `0x01 \|\| algorithme \|\| nonce (24 B) \|\| ciphertext+tag` | Format versionné vérifiant strictement la longueur minimale, la version et la balise Poly1305 avant tout décodage JSON. |
| **AAD strict** | Contexte lié (`user_id`, type d'entité, `entity_id`) | Empêche toute attaque par permutation ou substitution de blocs chiffrés entre utilisateurs ou entre fiches. |
| **Vérification serveur** | Re-hachage `Argon2id` + `ANVIL_AUTH_PEPPER` optionnel | Empêche qu'une compromission passive de la base serveur permette d'usurper une session sans passer par le KDF serveur. |
| **Jetons de session** | JWT `Ed25519` (`EdDSA`, 15 min) + Refresh Token opaque `SHA-256` | Chaque rafraîchissement consomme le jeton courant ; toute réutilisation révoque immédiatement la famille de sessions complète (`401`). |

---

## 2. Sûreté Mémoire, Lints & Durcissement Processus

Anvil applique une politique défensive uniforme sur l'ensemble du workspace Rust (`Cargo.toml`) :

- **Zero *unsafe* par défaut** : `[workspace.lints.rust]` configure `unsafe_code = "forbid"` (et `deny` sur `anvil-desktop` uniquement si requis par l'intégration fenêtre native).
- **Zéro panique en production** : `[workspace.lints.clippy]` interdit `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented` et `dbg_macro` via `-D warnings` en CI.
- **Effacement mémoire (`Zeroize` / `ZeroizeOnDrop`)** : `MasterSecret`, `MasterEncryptionKey`, `VaultKey`, secrets TOTP et buffers de secrets de configuration sont encapsulés dans des types `ZeroizeOnDrop` ou `Zeroizing` et effacés lors du verrouillage.
- **Masquage des journaux (`Debug` redacté)** : `ServerConfig`, `DatabaseConfig` et les structures secrètes de `anvil-core` masquent automatiquement toute valeur secrète sous `[REDACTED]` (vérifié par tests automatisés).
- **Suppression des *core dumps*** : les conteneurs Docker imposent `ulimits: core: 0` et l'unité systemd exemple active `LimitCORE=0`, `MemoryDenyWriteExecute=true`, `NoNewPrivileges=true` et `CapabilityBoundingSet=`.
- **Pile TLS 100 % Rust** : `deny.toml` bannit `openssl-sys` et `native-tls` au profit exclusif de `rustls` + `webpki-roots`.

---

## 3. Modèle de Menaces & Limites Connues

### Ce que le modèle protège

1. **Serveur compromis en lecture (base PostgreSQL/SQLite ou sauvegardes dérobées)** : l'attaquant n'obtient que des enveloppes `XChaCha20-Poly1305` authentifiées, des sels et des empreintes `Argon2id` poivrées ; aucun secret du coffre n'est lisible.
2. **Substitution de données en base** : la modification, le déplacement ou la réattribution d'un `ciphertext` échoue à la vérification Poly1305 grâce à l'AAD strict (`user_id`, type, identifiant).
3. **Énumération de comptes sur `/api/v1/prelogin`** : le serveur renvoie un sel déterministe dérivé via HMAC (`ANVIL_PRELOGIN_SECRET`) même pour une adresse inexistante.
4. **Vol de Refresh Token** : la détection de rejeu révoque instantanément toute la lignée de session associée.
5. **Rebonds SSRF via le proxy de favicons** : désactivé par défaut (`ANVIL_ENABLE_FAVICON_PROXY=false`) ; lorsqu'il est activé, le validateur bloque adresses IP littérales, boucles locales, RFC 1918, link-local, métadonnées cloud (`169.254.169.254`) et plages CGNAT avant connexion.

### Limites connues (hors modèle Zero-Knowledge)

- **Appareil client compromis** : un enregistreur de frappes, un débogueur attaché ou un programme malveillant disposant des droits utilisateur sur un poste déjà déverrouillé peut lire la mémoire vive ou le presse-papiers avant son nettoyage automatique.
- **Métadonnées visibles par l'hébergeur** : le serveur observe les adresses email de compte, rôles (`admin`/`user`), horodatages de création/modification, compteurs de fiches/dossiers/blobs, tailles des paquets chiffrés, numéros `revision`, `key_version`, adresses IP de connexion et domaines demandés si le proxy de favicons est activé.
- **Inscriptions** : fermées par défaut (`ANVIL_ALLOW_SIGNUPS=false`). Tout déploiement public sans contrôle d'invitations augmente l'exposition au spam ou aux attaques par saturation.

---

## 4. Rotation du Mot de Passe & Rotation d'Urgence de `VaultKey`

### Rotation standard du Master Password

`POST /api/v1/account/rotate-password` met à jour l'empreinte d'authentification et ré-enveloppe la `VaultKey` existante sous une nouvelle `MasterEncryptionKey` dérivée du nouveau mot de passe, sans modifier le contenu chiffré des fiches.

### Rotation d'urgence de `VaultKey` (appareil perdu ou compromis)

Si un appareil disposant d'un déverrouillage biométrique ou d'un cache local est suspecté de compromission :

1. Côté client, `ClientSyncEngine::emergency_rotate_vault_key` génère une nouvelle `VaultKey` 256 bits CSPRNG, ré-enveloppe cette clé sous la `MasterEncryptionKey` et re-chiffre localement l'intégralité des dossiers, fiches et blobs actifs avec le nouveau numéro de `key_version`.
2. La requête atomique `POST /api/v1/account/rotate-vault-key` vérifie côté serveur le `key_version` attendu, le `base_revision`, l'exhaustivité exacte à 100 % des entités actives (`IncompleteBatch` en cas d'écart), applique toute la rotation en transaction SQLite ou PostgreSQL, journalise l'événement `"vault_key_emergency_rotated"` et peut révoquer toutes les autres sessions actives.
3. En local, `emergency_rotate_vault_key` efface `biometric_sealed_vault_key` du cache SQLite et remplace les clés actives en RAM via `VaultLockManager::replace_vault_keys`.

Toute copie antérieure de l'ancienne `VaultKey` (y compris scellée dans un enclave biométrique sur un autre appareil) devient immédiatement inopérante pour les nouvelles données comme pour les sauvegardes synchronisées après rotation.

---

## 5. Isolation Extension Navigateur & Mobile OS

- **Extension MV3 (`apps/extension`)** :
  - Exécute la crypto en mémoire linéaire WebAssembly (`anvil-wasm`) et verrouille la session sur alarme d'inactivité.
  - Applique un filtre anti-phishing `eTLD+1` (`psl`) et une normalisation Punycode avant tout remplissage automatique ou suggestion d'identifiants.
  - Injecte le menu de suggestion dans un **Shadow DOM fermé** (`mode: "closed"`) afin d'empêcher les scripts de la page hôte de lire les secrets ou d'intercepter le DOM d'Anvil.
- **Mobile (`apps/mobile`)** :
  - Stocke le scellement biométrique via `tauri-plugin-biometric` dans **Android Keystore** ou **iOS Secure Enclave / App Group Keychain** (`io.anvil.vault.mobile.autofill`) sans conserver le Master Password sur disque.

---

## 6. Fuzzing, Tests Adversariaux & Audit

La suite de vérification inclut en permanence :

- **Fuzzing libFuzzer (`fuzz/`)** : `fuzz_aead_envelope`, `fuzz_totp_uri` et `fuzz_importers` (exécutés en smoke-run CI sur toolchain nightly).
- **Fuzzing déterministe `proptest` (`crates/anvil-core/tests/adversarial_fuzz.rs`)** : vérification d'absence de panique sur des octets aléatoires et contrôle de redaction `Debug`.
- **Tests adversariaux HTTP (`crates/anvil-server/tests/adversarial_security.rs`)** : corpus d'injection SQL, matrice SSRF complète et vérification de non-fuite de configuration.
- **Chaîne d'approvisionnement** : contrôle `cargo-audit`, `cargo-deny` (`deny.toml`), génération de SBOM CycloneDX et attestations de provenance sur les artefacts de release.

---

## 7. Divulgation Responsable

En cas de découverte d'une vulnérabilité affectant la cryptographie, l'isolation multi-utilisateurs, le serveur HTTP, l'extension navigateur ou les clients natifs :

- **Ne créez pas d'issue publique** détaillant l'exploitation avant correction.
- Utilisez un signalement privé via l'onglet **Security Advisories** du dépôt `https://github.com/Viectra/anvil` en joignant version concernée, environnement, étapes de reproduction minimales et impact estimé.
