# Bitcoin Mempool Listener & Header Tracker

L'objectif de ce projet est de construire un outil backend en ligne de commande, robuste, bien architecturé et massivement testé, sans s'encombrer de fonctionnalités superflues.

Il s'agit d'un client réseau Bitcoin autonome (SPV-light) capable de se connecter à des nœuds du réseau (ici configuré pour Regtest), de se synchroniser partiellement, et d'écouter les annonces de transactions du mempool en temps réel.

---

## 🟢 Ce que le projet implémente (Le Périmètre)

### 1. Le Socle Réseau et Protocole (Robustesse)
* **Handshake complet** : Échange des messages `version` et `verack` pour établir proprement la liaison avec le pair distant.
* **Heartbeat (Keep-alive)** : Réponse automatique aux requêtes `ping` par un `pong` pour maintenir la socket TCP active.
* **Gestion des erreurs réseau** : Reconnexion automatique asynchrone et gestion propre des timeouts de connexion.

### 2. Synchronisation Légère (SPV)
* **Téléchargement des en-têtes** : Envoi de `getheaders` et parsing des messages `headers` pour reconstituer la chaîne de blocs locale (uniquement les en-têtes de 80 octets, sans le contenu des blocs).
* **Validation PoW basique** : Recalcul du double SHA-256 de chaque en-tête reçu pour vérifier mathématiquement sa validité face à la difficulté annoncée.

### 3. Le Moniteur de Mempool (Temps Réel)
* **Écoute des annonces** : Interception des messages `inv` (Inventories) envoyés par les pairs lors de la découverte de nouvelles transactions.
* **Récupération ciblée** : Demande explicite des détails d'une transaction via le message `getdata`.
* **Parsing des transactions** : Décodage binaire des messages `tx` pour extraire et afficher le TXID (hash de la transaction), ainsi que ses entrées (inputs) et sorties (outputs).

### 4. Architecture Industrielle et Outillage
* **CLI Avancée** : Paramétrage complet via [clap](https://crates.io/crates/clap) (ex: `--network testnet`, `--peer 1.2.3.4:8333`, `--log-level debug`).
* **Observabilité** : Logger asynchrone structuré via la stack [tracing](https://crates.io/crates/tracing) au lieu de simples macros `println!`.
* **Tests Automatisés** : Suite rigoureuse de tests unitaires isolés se concentrant sur la sérialisation et la désérialisation binaire pour garantir la résilience des parsers face aux données corrompues.

---

## 🛑 Ce que le projet N'IMPLÉMENTERA PAS (Les Limites)

Afin de préserver un code propre et hautement spécialisé sur la tuyauterie réseau, les aspects suivants sont hors périmètre :

* ❌ **Téléchargement des blocs complets** : Aucun traitement des messages `block`. On ne télécharge et ne stocke que les en-têtes de blocs.
* ❌ **Validation du consensus** : Pas de vérification des signatures cryptographiques (ECDSA/Schnorr) ni contrôle des double-dépenses. Le client fait confiance aux pairs connectés.
* ❌ **Gestion de portefeuille (Wallet)** : Aucune gestion de clés privées, signature de transactions ou création d'envois.
* ❌ **Interface Utilisateur (UI/GUI)** : L'application reste exclusivement un démon CLI en arrière-plan ou interactif dans le terminal.
* ❌ **Minage** : Pas de résolution locale de Proof-of-Work.

---

## 💡 Intérêt Technique de ce Périmètre

Ce projet permet de consolider et de valider plusieurs compétences fondamentales en Rust :
1. **Manipulation binaire de bas niveau** : Parsing exact de structures de données binaires du protocole Bitcoin.
2. **Programmation concurrente asynchrone** : Orchestration robuste des entrées/sorties (réseau, terminal, timers) grâce à [tokio](https://crates.io/crates/tokio).
3. **Ingénierie de test** : Conception de parsers isolés et testables unitairement de manière intensive.
