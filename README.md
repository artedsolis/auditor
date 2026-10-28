<div align="center">

# 🛡️ Secure-Box

**L'Auditeur Flash — Audit express de sécurité pour serveurs Linux**

Analysez l'état de sécurité d'un serveur en quelques secondes et obtenez un mini-rapport clair : **Succès ✅ / Attention ⚠️ / Danger 🚨**

![Bash](https://img.shields.io/badge/Bash-5%2B-4EAA25?logo=gnu-bash&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux-FAF8E9?logo=linux&logoColor=black)
![No deps](https://img.shields.io/badge/D%C3%A9pendances-Aucune-brightgreen)
![Status](https://img.shields.io/badge/Statut-Op%C3%A9rationnel-success)

</div>

---

## 📖 Principe

`secure-box.sh` est un script Bash autonome qui **audite, rappelle et agit** :

| Menu | Mode | Description |
|------|------|-------------|
| `1` | **[Audit]** | Audit flash complet : SSH, mises à jour, permissions, pare-feu |
| `2` | **[Rappel]** | Commandes prêtes à copier pour bloquer une IP suspecte |
| `3` | **[Action]** | Fermeture immédiate d'un port selon le pare-feu détecté |

Chaque contrôle renvoie un statut coloré :

```
[OK]   Succès       ✅  — la configuration est saine
[!!]   Attention    ⚠️  — point à surveiller ou à améliorer
[XX]   Danger       🚨  — corrective urgente nécessaire
```

---

## 🔍 Ce que vérifie l'audit flash

### 🔐 SSH (`/etc/ssh/sshd_config`)
- `PermitRootLogin` : la connexion directe en `root` est-elle interdite ?
- `PasswordAuthentication` : authentification par mot de passe (brute-force)
- Service `sshd` actif

### 🔄 Mises à jour de sécurité
- Paquets de sécurité en attente (`apt` / `apt-check` / `dnf` / `yum`)
- Tentatives échouées de connexion dans les logs (`auth.log`, `secure`)

### 📁 Droits critiques
- Permissions des fichiers sensibles : `/etc/passwd`, `/etc/shadow`, `/etc/group`
- Fichiers de `/etc` en **écriture pour tout le monde** (`-perm -o+w`)
- Binaires **SUID** (inventaire rapide)

### 🧱 Pare-feu
- Détection automatique : **ufw**, **firewalld**, **nftables**, **iptables**
- Alerte `[XX]` si aucun pare-feu actif

---

## 🚀 Installation

```bash
# 1. Récupérer le script
git clone https://github.com/<votre-user>/auditor.git
cd auditor

# 2. Rendre exécutable
chmod +x secure-box.sh

# 3. Lancer (sudo recommandé pour un audit complet)
sudo ./secure-box.sh
```

> **Aucune dépendance externe.** Le script n'utilise que les outils déjà présents sur le serveur.

---

## 🖥️ Exemple de sortie

```text
╔══════════════════════════════════════════════╗
║        L'AUDITEUR FLASH  —  secure-box       ║
╚══════════════════════════════════════════════╝

  1. [Audit]   Vérifier l'état du SSH et du Pare-feu (+ MAJ, permissions)
  2. [Rappel] Afficher les commandes pour bloquer une IP suspecte
  3. [Action]  Fermer immédiatement un port spécifique
  q. Quitter

── Audit SSH ─────────────────────────
  [OK]   Connexion SSH en root interdite (PermitRootLogin no)
  [!!]   PasswordAuthentication activé (brute-force possible sur root)

── Audit Mises à jour ────────────────
  [XX]   3 mise(s) à jour de sécurité en attente -> apt-get upgrade

── Audit Droits / Permissions ────────
  [OK]   /etc/shadow permissions correctes (640)
  [XX]   2 fichier(s) de /etc accessibles en ÉCRITURE à tout le monde

── Audit Pare-feu ────────────────────
  [OK]   ufw actif

── MINI-RAPPORT ──────────────────────
  Succès : 3   Attention : 1   Danger : 2

  ⚠ DANGER — des actions correctives urgentes sont nécessaires.
```

---

## 🛠️ Action : fermer un port

À l'option `3`, le script détecte le pare-feu actif et applique le bon blocage :

| Pare-feu | Commande appliquée |
|----------|--------------------|
| `ufw` | `ufw deny <port>/<proto>` |
| `firewalld` | `firewall-cmd --remove-port` + fallback *rich rule* `reject` |
| `iptables` | `iptables -I INPUT 1 -p <proto> --dport <port> -j DROP` |
| `nftables` | `nft add rule inet filter input <proto> dport <port> drop` |

> 💡 `iptables` n'est pas persistant : pensez à `iptables-save > /etc/iptables/rules.v4`.

---

## 🧯 Rappel : bloquer une IP suspecte

L'option `2` affiche les commandes selon le pare-feu :

```bash
# ufw
sudo ufw deny from 198.51.100.23

# iptables
sudo iptables -I INPUT 1 -s 198.51.100.23 -j DROP

# firewalld
sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=198.51.100.23 reject'
sudo firewall-cmd --reload

# fail2ban (anti brute-force SSH)
sudo fail2ban-client set sshd banip 198.51.100.23
```

---

## ⚙️ Compatibilité

| Distribution | Audit SSH | Mises à jour | Pare-feu |
|--------------|-----------|--------------|----------|
| Debian / Ubuntu | ✅ | ✅ `apt` | ✅ `ufw` |
| CentOS / RHEL / Rocky | ✅ | ✅ `dnf`/`yum` | ✅ `firewalld` |
| Autres | ✅ | ⚠️ manuel | ✅ détection auto |

> ⚠️ Le script est conçu pour **GNU/Linux**. Sur macOS il s'exécute mais les tests ne s'appliquent pas.

---

## 🗂️ Structure du projet

```text
auditor/
└── secure-box.sh    # L'Auditeur Flash (audit + rappel + action)
```

---

## 💡 Bonnes pratiques ciblées

- Interdire le login SSH direct en `root` (`PermitRootLogin no`)
- Privilégier l'authentification par **clés SSH**
- Maintenir le système à jour (paquets de sécurité)
- Toujours avoir un **pare-feu actif** (ufw, firewalld, nftables)
- Mettre en place **fail2ban** contre le brute-force

---

## ⚠️ Avertissement

Ce script fournit un **état des lieux rapide**, non un audit exhaustif. Il ne modifie aucune configuration sans validation explicite de votre part (sauf l'option **[Action]** qui agit immédiatement sur le pare-feu). À utiliser sur vos propres serveurs.

---

<div align="center">

**Secure-Box** — audit express, décisions éclairées. 🛡️

</div>
