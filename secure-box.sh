#!/usr/bin/env bash
# ============================================================================
#  secure-box.sh — L'Auditeur Flash (Audit express de sécurité)
#  Analyse rapide de l'état de sécurité d'un serveur Linux :
#    - Accès SSH (PermitRootLogin)
#    - Mises à jour de sécurité en attente
#    - Droits critiques (fichiers trop permissifs)
#    - Pare-feu (ufw / firewalld / iptables)
#  Chaque contrôle renvoie : [OK] Succès / [!!] Attention / [XX] Danger
# ============================================================================

set -u

# ----------------------------- Couleurs & styles ----------------------------
if [[ -t 1 ]]; then
    ROUGE=$'\033[1;31m'; VERT=$'\033[1;32m'; JAUNE=$'\033[1;33m'
    CYAN=$'\033[1;36m'; GRIS=$'\033[0;37m'; GRAS=$'\033[1m'; NC=$'\033[0m'
else
    ROUGE=""; VERT=""; JAUNE=""; CYAN=""; GRIS=""; GRAS=""; NC=""
fi

ok()     { printf "  %s[OK]%s   %s\n"      "$VERT"  "$NC" "$1"; }
warn()   { printf "  %s[!!]%s   %s\n"      "$JAUNE" "$NC" "$1"; }
danger() { printf "  %s[XX]%s   %s\n"      "$ROUGE" "$NC" "$1"; }
info()   { printf "  %s[i]%s    %s\n"      "$CYAN"  "$NC" "$1"; }
titre()  { printf "\n%s── %s ─────────────────────────%s\n" "$GRAS$CYAN" "$1" "$NC"; }

has() { command -v "$1" >/dev/null 2>&1; }

# Compteur global des anomalies pour le mini-verdict final
NB_OK=0; NB_WARN=0; NB_DANGER=0

res_ok()     { NB_OK=$((NB_OK+1));     ok "$1"; }
res_warn()   { NB_WARN=$((NB_WARN+1)); warn "$1"; }
res_danger() { NB_DANGER=$((NB_DANGER+1)); danger "$1"; }

# ----------------------------- Prérequis ------------------------------------
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "${ROUGE}Ce script est conçu pour auditer un serveur Linux (GNU/Linux).${NC}"
    echo "Plateforme détectée : $(uname -s) — les tests risquent de ne pas s'appliquer."
fi

IS_ROOT=0
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    IS_ROOT=1
fi

# ----------------------------------------------------------------------------
# 1) AUDIT SSH  —  PermitRootLogin, authentification vide, version du protocole
# ----------------------------------------------------------------------------
audit_ssh() {
    titre "Audit SSH"

    local ssd_cfg="/etc/ssh/sshd_config"
    if [[ ! -f "$ssd_cfg" ]]; then
        res_warn "Fichier $ssd_cfg introuvable (OpenSSH non installé ?)"
        return
    fi

    if [[ $IS_ROOT -eq 0 && ! -r "$ssd_cfg" ]]; then
        res_warn "Impossible de lire $ssd_cfg — relancez avec sudo"
        return
    fi

    local root_line
    root_line=$(grep -Ei '^\s*#?\s*PermitRootLogin' "$ssd_cfg" | tail -n 1)

    if [[ -z "$root_line" ]]; then
        res_warn "Directive PermitRootLogin absente (comportement par défaut selon la distro)"
    elif echo "$root_line" | grep -qiE 'no$|without-password$|prohibit-password$'; then
        if echo "$root_line" | grep -qE '^\s*#'; then
            res_warn "PermitRootLogin désactivé uniquement par défaut (ligne commentée)"
        else
            res_ok "Connexion SSH en root interdite ($(echo "$root_line" | tr -s ' ' | xargs))"
        fi
    else
        res_danger "CONNEXION ROOT AUTORISÉE via SSH -> corrigez PermitRootLogin no"
    fi

    local pass_auth
    pass_auth=$(grep -Ei '^\s*PermitRootLogin\s+yes' "$ssd_cfg" | tail -n 1)
    : # (résultat déjà traité ci-dessus)

    if grep -qiE '^\s*PasswordAuthentication\s+no' "$ssd_cfg"; then
        res_ok "Authentification par mot de passe désactivée (clés recommandées)"
    else
        res_warn "PasswordAuthentication activé (brute-force possible sur root)"
    fi

    if has sshd || [[ -d /run/sshd ]]; then
        if pgrep -x sshd >/dev/null 2>&1; then
            info "Service sshd actif"
        fi
    fi
}

# ----------------------------------------------------------------------------
# 2) AUDIT MISES À JOUR  —  paquets de sécurité en attente
# ----------------------------------------------------------------------------
audit_updates() {
    titre "Audit Mises à jour"

    if has apt-check || [[ -x /usr/lib/update-notifier/apt-check ]]; then
        local out
        out=$(/usr/lib/update-notifier/apt-check --human-readable 2>/dev/null || apt-check --human-readable 2>/dev/null)
        if echo "$out" | grep -qi "security updates"; then
            local nb
            nb=$(echo "$out" | grep -oiE '[0-9]+ security update' | grep -oiE '[0-9]+' | head -n1)
            if [[ "${nb:-0}" -gt 0 ]]; then
                res_danger "$nb mise(s) à jour de sécurité en attente -> apt-get upgrade"
            else
                res_ok "Aucune mise à jour de sécurité en attente"
            fi
        else
            res_ok "Aucune mise à jour de sécurité en attente (apt)"
        fi
    elif has apt-get; then
        local nb
        nb=$(apt-get -s upgrade 2>/dev/null | grep -icE 'inst.*security|security.*inst' )
        if [[ "${nb:-0}" -gt 0 ]]; then
            res_danger "≈$nb paquet(s) de sécurité à installer -> apt-get upgrade"
        else
            warn "Impossible de compter les mises à jour de sécurité avec précision (apt)"
            info "Pensez à lancer : sudo apt-get update && sudo apt-get upgrade"
        fi
    elif has dnf || has yum; then
        local pm="dnf"; has dnf || pm="yum"
        local nb
        nb=$($pm -q check-update --security 2>/dev/null | grep -cE '^[a-z0-9]' )
        if [[ "${nb:-0}" -gt 0 ]]; then
            res_danger "≈$nb mise(s) à jour de sécurité en attente -> $pm upgrade"
        elif [[ $? -eq 0 ]]; then
            res_ok "Aucune mise à jour de sécurité en attente ($pm)"
        else
            warn "Vérification des mises à jour indisponible ($pm)"
        fi
    else
        res_warn "Gestionnaire de paquets non reconnu — vérifiez les mises à jour manuellement"
    fi

    if has last && [[ -r /var/log/auth.log || -r /var/log/secure ]]; then
        local logs="/var/log/auth.log"; [[ -r "$logs" ]] || logs="/var/log/secure"
        local fails
        fails=$(grep -icE 'authentication failure|Failed password' "$logs" 2>/dev/null || echo 0)
        if [[ "${fails:-0}" -ge 50 ]]; then
            res_warn "$fails tentatives de connexion échouées détectées dans $logs (brute-force ?)"
        else
            res_ok "Peu de tentatives échouées dans $logs ($fails)"
        fi
    fi
}

# ----------------------------------------------------------------------------
# 3) AUDIT DROITS CRITIQUES  —  fichiers permissifs & fichiers sensibles
# ----------------------------------------------------------------------------
audit_permissions() {
    titre "Audit Droits / Permissions"

    if [[ $IS_ROOT -eq 0 ]]; then
        res_warn "Audit partiel : relancez avec sudo pour une analyse complète"
    fi

    # Fichiers sensibles du système
    local f perms
    for f in /etc/passwd /etc/shadow /etc/group; do
        [[ -e "$f" ]] || continue
        perms=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%Lp' "$f" 2>/dev/null)
        case "$f" in
            /etc/shadow)
                if [[ "$perms" == "640" || "$perms" == "600" || "$perms" == "000" ]]; then
                    res_ok "$f permissions correctes ($perms)"
                else
                    res_danger "$f permissions dangereuses ($perms) -> chmod 640 $f"
                fi ;;
            *)
                if [[ "$perms" == "644" || "$perms" == "640" || "$perms" == "600" ]]; then
                    res_ok "$f permissions correctes ($perms)"
                else
                    res_danger "$f permissions dangereuses ($perms) -> chmod 644 $f"
                fi ;;
        esac
    done

    # Fichiers en écriture pour tout le monde dans /etc (monde inscriptible = danger)
    local ww count=0
    ww=$(find /etc -xdev -perm -o+w -type f 2>/dev/null)
    count=$(echo "$ww" | grep -c . )
    if [[ "${count:-0}" -gt 0 ]]; then
        res_danger "$count fichier(s) de /etc accessibles en ÉCRITURE à tout le monde :"
        while IFS= read -r file; do [[ -n "$file" ]] && printf "         %s%s%s\n" "$GRIS" "$file" "$NC"; done <<< "$ww"
    else
        res_ok "Aucun fichier de /etc en écriture mondiale"
    fi

    # Fichiers SUID suspects (hors binaires classiques) — rapide, limité à /usr et /bin
    local suid_count
    suid_count=$(find /usr /bin /sbin -xdev -perm -4000 -type f 2>/dev/null | wc -l | tr -d ' ')
    if [[ "${suid_count:-0}" -gt 0 ]]; then
        info "$suid_count binaire(s) SUID trouvés (à vérifier manuellement)"
    fi
}

# ----------------------------------------------------------------------------
# 4) AUDIT PARE-FEUE  —  ufw / firewalld / iptables / nftables
# ----------------------------------------------------------------------------
detect_firewall() {
    FIREWALL="none"
    if has ufw && ufw status 2>/dev/null | grep -qi "Status: active"; then
        FIREWALL="ufw"
    elif has firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
        FIREWALL="firewalld"
    elif has nft && [[ $IS_ROOT -eq 1 ]] && nft list ruleset 2>/dev/null | grep -qi chain; then
        FIREWALL="nftables"
    elif has iptables && [[ $IS_ROOT -eq 1 ]] && iptables -L INPUT -n 2>/dev/null | grep -vqc 'chain\|target'; then
        FIREWALL="iptables"
    fi
}

audit_firewall() {
    titre "Audit Pare-feu"
    detect_firewall
    case "$FIREWALL" in
        ufw)        res_ok "ufw actif" ;;
        firewalld)  res_ok "firewalld actif" ;;
        nftables)   res_ok "nftables actif (règles présentes)" ;;
        iptables)   res_ok "iptables actif (règles INPUT présentes)" ;;
        *)          res_danger "AUCUN PARE-FEUE ACTIF détecté -> installez ufw ou configurez iptables" ;;
    esac
}

# ----------------------------------------------------------------------------
# Mini-verdict final
# ----------------------------------------------------------------------------
verdict() {
    titre "MINI-RAPPORT"
    printf "  %sSuccès : %d%s   %sAttention : %d%s   %sDanger : %d%s\n" \
        "$VERT" "$NB_OK" "$NC" "$JAUNE" "$NB_WARN" "$NC" "$ROUGE" "$NB_DANGER" "$NC"
    echo
    if [[ $NB_DANGER -gt 0 ]]; then
        echo "  ${ROUGE}${GRAS}⚠ DANGER — des actions correctives urgentes sont nécessaires.${NC}"
    elif [[ $NB_WARN -gt 0 ]]; then
        echo "  ${JAUNE}${GRAS}⚠ ATTENTION — état globalement acceptable, points à surveiller.${NC}"
    else
        echo "  ${VERT}${GRAS}✓ SUCCÈS — aucune anomalie détectée sur les contrôles effectués.${NC}"
    fi
}

# ----------------------------------------------------------------------------
# Option 1 — Audit complet (SSH + Mises à jour + Permissions + Pare-feu)
# ----------------------------------------------------------------------------
do_audit() {
    if [[ $IS_ROOT -eq 0 ]]; then
        warn "Vous n'êtes pas root : certains contrôles seront limités (sudo recommandé)"
    fi
    NB_OK=0; NB_WARN=0; NB_DANGER=0
    audit_ssh
    audit_updates
    audit_permissions
    audit_firewall
    verdict
}

# ----------------------------------------------------------------------------
# Option 2 — Rappel des commandes pour bloquer une IP suspecte
# ----------------------------------------------------------------------------
do_rappel() {
    titre "RAPPEL — Bloquer une IP suspecte"
    echo "  ${GRAS}Selon votre pare-feu (${FIREWALL}) :${NC}\n"
    echo "  ${CYAN}# ufw :${NC}"
    echo "    sudo ufw deny from 198.51.100.23                 # bloquer une IP"
    echo "    sudo ufw deny from 198.51.100.0/24               # bloquer un réseau"
    echo "    sudo ufw status numbered                          # lister/rappeler les règles\n"
    echo "  ${CYAN}# iptables :${NC}"
    echo "    sudo iptables -A INPUT -s 198.51.100.23 -j DROP  # bloquer une IP"
    echo "    sudo iptables -I INPUT 1 -s 198.51.100.23 -j DROP# bloquer en priorité"
    echo "    sudo iptables -L INPUT -n -v                      # lister les règles\n"
    echo "  ${CYAN}# firewalld :${NC}"
    echo "    sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=198.51.100.23 reject'"
    echo "    sudo firewall-cmd --reload\n"
    echo "  ${CYAN}# Fail2ban (recommandé contre le brute-force SSH) :${NC}"
    echo "    sudo fail2ban-client status sshd                  # IP bannies actuellement"
    echo "    sudo fail2ban-client set sshd banip 198.51.100.23# bannir une IP manuellement"
}

# ----------------------------------------------------------------------------
# Option 3 — Action : fermer immédiatement un port
# ----------------------------------------------------------------------------
do_action() {
    titre "ACTION — Fermer un port"
    local port proto
    read -rp "  Numéro du port à fermer (ex : 22, 3306) : " port
    if ! [[ "$port" =~ ^[0-9]{1,5}$ ]] || [[ $port -lt 1 || $port -gt 65535 ]]; then
        danger "Port invalide"
        return
    fi
    read -rp "  Protocole [tcp/udp] (défaut : tcp) : " proto
    proto=${proto:-tcp}
    if [[ "$proto" != "tcp" && "$proto" != "udp" ]]; then
        danger "Protocole invalide"
        return
    fi

    detect_firewall
    if [[ $IS_ROOT -eq 0 ]]; then
        danger "Nécessite les droits root (sudo $0)"
        return
    fi

    echo
    case "$FIREWALL" in
        ufw)
            if ufw deny "$port/$proto" 2>/dev/null; then
                res_ok "ufw : blocage de $proto/$port appliqué"
            else
                danger "ufw : échec du blocage"
            fi ;;
        firewalld)
            if firewall-cmd --permanent --remove-port="$port/$proto" 2>/dev/null \
               && firewall-cmd --reload 2>/dev/null; then
                res_ok "firewalld : port $port/$proto retiré des règles autorisées"
            else
                warn "firewalld : le port n'était peut-être pas ouvert ; ajout d'un blocage riche"
                firewall-cmd --permanent \
                    --add-rich-rule="rule family=ipv4 port port=$port protocol=$proto reject" 2>/dev/null \
                    && firewall-cmd --reload 2>/dev/null \
                    && res_ok "firewalld : $proto/$port rejeté" \
                    || danger "firewalld : échec du blocage"
            fi ;;
        nftables)
            if nft add rule inet filter input $proto dport $port drop 2>/dev/null; then
                res_ok "nftables : règle de drop ajoutée pour $proto/$port"
            else
                danger "nftables : chaîne 'inet filter input' introuvable — à ajouter manuellement"
            fi ;;
        iptables)
            if iptables -I INPUT 1 -p "$proto" --dport "$port" -j DROP 2>/dev/null; then
                res_ok "iptables : DROP inséré en priorité 1 pour $proto/$port"
                info "Note : non persistant après redémarrage (iptables-save > /etc/iptables/rules.v4)"
            else
                danger "iptables : échec de l'insertion de la règle"
            fi ;;
        *)
            danger "Aucun pare-feu actif : impossible de fermer le port via ce script"
            info "Installez ufw (apt install ufw && ufw enable) ou configurez iptables"
            ;;
    esac
}

# ----------------------------------------------------------------------------
# Menu principal
# ----------------------------------------------------------------------------
banniere() {
    clear 2>/dev/null || true
    printf "%s╔══════════════════════════════════════════════╗%s\n" "$GRAS$CYAN" "$NC"
    printf "%s║        L'AUDITEUR FLASH  —  secure-box       ║%s\n" "$GRAS$CYAN" "$NC"
    printf "%s╚══════════════════════════════════════════════╝%s\n" "$GRAS$CYAN" "$NC"
}

menu() {
    echo
    printf "  %s1.%s [Audit]   Vérifier l'état du SSH et du Pare-feu (+ MAJ, permissions)\n" "$GRAS" "$NC"
    printf "  %s2.%s [Rappel] Afficher les commandes pour bloquer une IP suspecte\n" "$GRAS" "$NC"
    printf "  %s3.%s [Action]  Fermer immédiatement un port spécifique\n" "$GRAS" "$NC"
    printf "  %sq.%s Quitter\n" "$GRAS" "$NC"
    echo
}

main() {
    while true; do
        banniere
        menu
        read -rp "  Choix [1-3] : " choix
        case "$choix" in
            1) do_audit ;;
            2) detect_firewall; do_rappel ;;
            3) do_action ;;
            q|Q|quit) echo "  Au revoir."; exit 0 ;;
            *) warn "Choix invalide" ;;
        esac
        echo
        read -rp "  Appuyez sur Entrée pour continuer..." _
    done
}

main "$@"
