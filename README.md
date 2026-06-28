# Bitcoin Mini-Node (SPV Light Client)

L'objectif de ce projet est de construire un client réseau Bitcoin autonome (SPV-light) depuis zéro en Rust, extrêmement performant et sans aucune dépendance superflue (adieu l'over-engineering !).

Il se connecte à des nœuds du réseau, se synchronise partiellement en téléchargeant les en-têtes de blocs, et maintient une architecture orientée "State Machine" stricte.

---

## 🟢 Progression du Développement

Voici la checklist de tout ce qui a été accompli et ce qu'il reste à faire.

### 1. Le Socle Réseau et Protocole (Robustesse)
- [x] **Handshake complet** : Échange des messages `version` et `verack`.
- [x] **Heartbeat (Keep-alive)** : Réponse automatique aux requêtes `ping` par un `pong`.
- [x] **Pool de Connexions** : Connexion asynchrone concurrente à plusieurs pairs (via `tokio`).
- [x] **State Machine (Sans-I/O)** : Découplage total de la logique métier (`protocol.rs`) et du réseau (`main.rs`) via un système d'Actions (`PeerAction`).
- [x] **Validation des paquets** : Parsing binaire robuste (Checksum, Magic bytes, longueurs) avec des tests unitaires contre la corruption de données.

### 2. Synchronisation Légère (SPV)
- [x] **Téléchargement des en-têtes** : Envoi de `getheaders` et parsing des messages `headers`.
- [x] **Validation PoW** : Vérification mathématique du Proof-of-Work (double SHA-256) des en-têtes.
- [x] **Persistance ultra-légère** : Sauvegarde des blocs sur disque en binaire pur (`headers.dat`, 80 octets/bloc) via un `BufWriter` pour minimiser les syscalls, sans utiliser de framework lourd comme `serde`.
- [x] **Reprise sur erreur** : Rechargement instantané de la chaîne depuis `headers.dat` au démarrage.

### 3. Interface et Observabilité
- [x] **Terminal User Interface (TUI)** : Affichage en direct du statut de synchronisation, des pairs connectés et des logs via `ratatui`.
- [x] **Lean Logging** : Utilisation de macros légères (`info!`, `error!`) directement branchées sur le TUI, sans usine à gaz comme `tracing`.

### 4. Ce qu'il reste à faire (Le Live Mempool & Wallet)
- [x] **Décodage des inventaires** : Parsing des messages `inv` annonçant de nouvelles données.
- [x] **Message GetData** : Implémentation et tests de la sérialisation de `getdata` pour réclamer le contenu.
- [x] **Aspirateur de Transactions** : Répondre automatiquement aux `inv` avec un `getdata` pour obtenir le détail des transactions.
- [x] **Décodage des TX** : Parser les messages `tx` pour afficher un radar en direct du mempool dans le TUI (Montants, Adresses, Frais).
- [ ] **Filtres de Bloom (`filterload`)** : Demander aux nœuds de ne relayer que les transactions d'une adresse spécifique.
- [ ] **Preuves SPV (`merkleblock`)** : Vérifier mathématiquement l'inclusion d'une transaction dans un bloc.
- [ ] **Watch-only Wallet** : Calculer et afficher un solde Bitcoin en temps réel à partir de la chaîne !

---

## 🛑 Ce que le projet N'IMPLÉMENTERA PAS (Les Limites)

* ❌ **Téléchargement des blocs complets** : Aucun traitement des messages `block`. On ne stocke que les en-têtes.
* ❌ **Validation du consensus** : Pas de vérification des signatures cryptographiques (ECDSA/Schnorr) ni contrôle des double-dépenses. Le client fait confiance aux preuves SPV.
* ❌ **Gestion de clés (Wallet actif)** : Aucune gestion de clés privées, signature de transactions ou création d'envois. C'est un outil de lecture uniquement.
* ❌ **Minage** : Pas de résolution locale de Proof-of-Work.

---

## ❄️ Exécution avec Nix

Ce projet supporte [Nix Flakes](https://nixos.wiki/wiki/Flakes) pour garantir un environnement de compilation et d'exécution parfaitement reproductible.

### Lancer le projet directement :
```bash
nix run
```

### Environnement de développement :
```bash
nix develop
cargo test
cargo run
```
