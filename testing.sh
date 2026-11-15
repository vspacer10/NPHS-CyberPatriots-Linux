#!/bin/bash

# ==============================================================================
# CYBERPATRIOT - LINUX MINT 21 (UBUNTU 22.04) HARDENER
# Usage:
#   sudo bash harden.sh                  # Full universal hardening + action report
#   sudo bash harden.sh --interactive    # Prompt for README users/admins/services
#   sudo bash harden.sh --skip-aide      # Skip slow AIDE baseline build at end
#   sudo bash harden.sh --scan-clamav    # Run ClamAV scan on /home /tmp /var/www
# ==============================================================================

set -o pipefail
export DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------------------
# OPTIONAL PRE-CONFIGURED README POLICY (Leave empty unless automating offline)
# Note: Only enforced if populated OR if --interactive is passed.
# ------------------------------------------------------------------------------
AUTHORIZED_ADMINS=()     # e.g. ("cyberpatriot" "alice")
AUTHORIZED_USERS=()      # e.g. ("bob" "charlie")
REQUIRED_SERVICES=()     # e.g. ("ssh" "apache2" "vsftpd")
DISABLE_USB_STORAGE=false

INTERACTIVE_MODE=false
SKIP_AIDE=false
RUN_CLAMSCAN=false
ROTATE_PASSWORDS=false
NEW_COMP_PASSWORD="Cyb3rPatri0tsPass"

for arg in "$@"; do
    case "$arg" in
        --interactive|-i) INTERACTIVE_MODE=true ;;
        --skip-aide)      SKIP_AIDE=true ;;
        --scan-clamav)    RUN_CLAMSCAN=true ;;
        --disable-usb)    DISABLE_USB_STORAGE=true ;;
        *) echo "Unknown flag: $arg" ;;
    esac
done

# --- ROOT CHECK ---
if [[ "${EUID}" -ne 0 ]]; then
    echo " (!) This script must be run as root (use sudo). Exiting."
    exit 1
fi

CURRENT_OPERATOR="${SUDO_USER:-$(logname 2>/dev/null || whoami)}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/cyberpatriot_hardening_${TIMESTAMP}.log"
REPORT_FILE="/root/CYBERPATRIOT_ACTION_REPORT.txt"
BACKUP_DIR="/var/backups/cyberpatriot_${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"

exec > >(tee -a "${LOG_FILE}") 2>&1

echo "=================================================================="
echo "  CyberPatriot Hardening Script (Linux Mint 21)"
echo "  Operator: ${CURRENT_OPERATOR} | Started: $(date)"
echo "  Log: ${LOG_FILE}"
echo "  Report: ${REPORT_FILE}"
echo "=================================================================="

# Initialize prioritized report
cat > "$REPORT_FILE" <<EOF
CYBERPATRIOT ACTION REPORT - $(date)
Operator: ${CURRENT_OPERATOR}
==================================================================
EOF

report_line() {
    echo "$1" >> "$REPORT_FILE"
}

add_or_update_sysctl() {
    local key="$1"
    local value="$2"
    local config_file="/etc/sysctl.d/99-cyberpatriot.conf"
    local escaped_key="${key//./\\.}"

    touch "${config_file}"
    if grep -qE "^\s*#?\s*${escaped_key}\s*=" "${config_file}"; then
        sed -i -e "s|^\s*#*\s*${escaped_key}\s*=.*|${key} = ${value}|g" "${config_file}"
    else
        echo "${key} = ${value}" >> "${config_file}"
    fi

    # Keep /etc/sysctl.conf consistent if key already exists there
    if [ -f /etc/sysctl.conf ] && grep -qE "^\s*#?\s*${escaped_key}\s*=" /etc/sysctl.conf; then
        sed -i -e "s|^\s*#*\s*${escaped_key}\s*=.*|${key} = ${value}|g" /etc/sysctl.conf
    fi
}

is_in_array() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

# --- INTERACTIVE README WIZARD (IF REQUESTED) ---
if [[ "$INTERACTIVE_MODE" == true ]]; then
    echo ""
    echo "--- INTERACTIVE README POLICY SETUP ---"
    echo "Enter values space-separated (press Enter to skip a category)."
    read -r -p "Authorized ADMINS (must include ${CURRENT_OPERATOR}): " -a AUTHORIZED_ADMINS
    read -r -p "Authorized STANDARD USERS (non-admins): " -a AUTHORIZED_USERS
    read -r -p "Required SERVICES (e.g. ssh apache2 nginx vsftpd smbd bind9 mysql postgresql): " -a REQUIRED_SERVICES
    read -r -p "Rotate passwords for all authorized users (except root)? [y/N]: " ans_pw
    if [[ "$ans_pw" =~ ^[Yy]$ ]]; then
        read -r -s -p "Enter new compliant password (14+ chars, upper+lower+digit+special): " NEW_COMP_PASSWORD
        echo ""
        if [[ ${#NEW_COMP_PASSWORD} -ge 14 ]]; then
            ROTATE_PASSWORDS=true
        else
            echo " (!) Password shorter than 14 chars; skipping automatic password rotation."
        fi
    fi
fi

# --- 1. REPOSITORY SECURITY, UPDATES & SECURITY TOOLS ---
echo ""
echo "--- SECTION 1: APT SECURITY, UPDATES & TOOLS ---"
mkdir -p /etc/apt/apt.conf.d
cat > /etc/apt/apt.conf.d/99-cyberpatriot-security <<EOF
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
EOF

# Check for insecure APT flags or unexpected third-party sources
report_line ""
report_line "[1] APT REPOSITORY AUDIT:"
grep -rnE "trusted=yes|http://" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null >> "$REPORT_FILE" || true

if apt-get update -y; then
    echo " (>) Upgrading installed packages..."
    apt-get upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" || echo " (!) apt-get upgrade warning"

    echo " (>) Installing security toolset..."
    SEC_PACKAGES=(
        ufw clamav clamav-daemon clamav-freshclam
        auditd audispd-plugins debsums chkrootkit
        libpam-pwquality libpam-apparmor apparmor-utils
        unattended-upgrades fail2ban libopenscap8 openscap-utils lynis
    )
    for pkg in "${SEC_PACKAGES[@]}"; do
        if apt-cache show "$pkg" &>/dev/null; then
            apt-get install -y --no-install-recommends "$pkg" || echo " (!) Failed to install $pkg"
        fi
    done
    for pkg in aide aide-common; do
        if apt-cache show "$pkg" &>/dev/null; then
            apt-get install -y --no-install-recommends "$pkg" || echo " (!) Failed to install $pkg"
        fi
    done
else
    echo " (!) apt-get update failed (offline or repository error). Continuing with local hardening."
fi

# Configure Unattended Upgrades
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable unattended-upgrades 2>/dev/null || true
systemctl start unattended-upgrades 2>/dev/null || true

# --- 2. ACCOUNT DEFAULTS, TMOUT, CRON/AT, STICKY BITS & SYSTEMD ---
echo ""
echo "--- SECTION 2: SHELL TIMEOUT, CRON/AT, BOOT & FILESYSTEM HARDENING ---"
useradd -D -f 30

# Guarded TMOUT in /etc/profile.d (never crashes LightDM/Xsession)
[ -f /etc/profile ] && sed -i '/^readonly TMOUT=/d;/^export TMOUT$/d' /etc/profile
mkdir -p /etc/profile.d
cat > /etc/profile.d/99-tmout.sh <<'EOF'
if [ -z "${TMOUT:-}" ]; then
    TMOUT=900
    readonly TMOUT
    export TMOUT
fi
EOF
chmod 644 /etc/profile.d/99-tmout.sh

# Restrict cron and at to root (CIS Benchmark)
rm -f /etc/cron.deny /etc/at.deny
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow
chmod 640 /etc/cron.allow /etc/at.allow

# Mask Ctrl-Alt-Del reboot & disable Apport/Whoopsie crash dumps
systemctl mask --now ctrl-alt-del.target 2>/dev/null || true
if [ -f /etc/default/apport ]; then
    sed -i 's/^enabled=.*/enabled=0/' /etc/default/apport
fi
systemctl stop apport whoopsie 2>/dev/null || true
systemctl disable apport whoopsie 2>/dev/null || true

# Enforce sticky bit on world-writable directories
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod +t {} + 2>/dev/null || true

# Remove legacy NIS '+' lines and rhosts files
for sysf in /etc/passwd /etc/shadow /etc/group /etc/gshadow; do
    if [ -f "$sysf" ] && grep -q '^+:' "$sysf"; then
        cp "$sysf" "${BACKUP_DIR}/$(basename "$sysf").nis.bak"
        sed -i '/^+:/d' "$sysf"
    fi
done
rm -f /etc/hosts.equiv /etc/shosts.equiv
find /home /root -maxdepth 3 \( -name ".rhosts" -o -name ".shosts" -o -name ".netrc" \) -delete 2>/dev/null || true

# --- 3. CLAMAV UPDATE ---
echo ""
echo "--- SECTION 3: CLAMAV ---"
if command -v freshclam &>/dev/null; then
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam || echo " (!) Freshclam failed (possibly offline)."
    systemctl enable clamav-freshclam 2>/dev/null || true
    systemctl start clamav-freshclam 2>/dev/null || true

    if ls /var/lib/clamav/*.c[vl]d &>/dev/null; then
        systemctl enable clamav-daemon 2>/dev/null || true
        systemctl start clamav-daemon 2>/dev/null || true
    fi
fi

# --- 4. LOGGING (JOURNALD, RSYSLOG & AUDITD) ---
echo ""
echo "--- SECTION 4: LOGGING & COMPREHENSIVE AUDITD ---"
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-cyberpatriot.conf <<EOF
[Journal]
Storage=persistent
Compress=yes
ForwardToSyslog=yes
EOF
systemctl restart systemd-journald 2>/dev/null || true

if [ -d /etc/rsyslog.d ]; then
    cat > /etc/rsyslog.d/99-cyberpatriot.conf <<EOF
\$FileCreateMode 0640
EOF
    systemctl enable rsyslog 2>/dev/null || true
    systemctl restart rsyslog 2>/dev/null || true
fi

if [ -d /etc/audit ]; then
    cp /etc/audit/auditd.conf "${BACKUP_DIR}/auditd.conf.bak" 2>/dev/null || true
    sed -i 's/^max_log_file_action.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action.*/space_left_action = SYSLOG/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = SUSPEND/' /etc/audit/auditd.conf

    mkdir -p /etc/audit/rules.d
    cat > /etc/audit/rules.d/99-cyberpatriot.rules <<'EOF'
-D
-b 8192
-f 1

# Time modifications
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Identity & privilege files
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions

# Network & hosts changes
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/netplan -p wa -k system-locale

# AppArmor & login tracking
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# DAC permissions & unauthorized access
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=unset -k perm_mod
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access

# Privilege escalation & kernel modules
-a always,exit -F arch=b64 -C uid!=euid -F euid=0 -S execve -k priv_esc
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules

# Lock rules until reboot
-e 2
EOF

    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true
    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        echo " (*) Auditd is in immutable mode (-e 2); new rules apply after reboot."
    else
        augenrules --load || echo " (!) augenrules --load warning"
    fi
fi

# --- 5. SUDOERS HARDENING & SANITIZATION ---
echo ""
echo "--- SECTION 5: SUDOERS HARDENING ---"
cp /etc/sudoers "${BACKUP_DIR}/sudoers.bak"
if [ -d /etc/sudoers.d ]; then
    cp -r /etc/sudoers.d "${BACKUP_DIR}/sudoers.d.bak"
fi

# Comment out NOPASSWD, !authenticate, and infinite timestamp_timeout=-1
if grep -qE '^[^#]*(NOPASSWD|!authenticate|timestamp_timeout=-1)' /etc/sudoers; then
    sed -i -E 's/^([^#]*(NOPASSWD|!authenticate|timestamp_timeout=-1).*)/# \1/' /etc/sudoers
fi
if [ -d /etc/sudoers.d ]; then
    grep -rlE '^[^#]*(NOPASSWD|!authenticate|timestamp_timeout=-1)' /etc/sudoers.d/ 2>/dev/null | while read -r sfile; do
        sed -i -E 's/^([^#]*(NOPASSWD|!authenticate|timestamp_timeout=-1).*)/# \1/' "$sfile"
    done
fi

cat > /etc/sudoers.d/99-cyberpatriot <<EOF
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        use_pty
Defaults        logfile="/var/log/sudo.log"
Defaults        timestamp_timeout=15
EOF
chmod 440 /etc/sudoers.d/99-cyberpatriot
chmod 755 /etc/sudoers.d
chmod 440 /etc/sudoers.d/* 2>/dev/null || true

if ! visudo -c; then
    echo " (!) visudo check failed! Restoring backup."
    cp "${BACKUP_DIR}/sudoers.bak" /etc/sudoers
    rm -f /etc/sudoers.d/99-cyberpatriot
fi

# --- 6. APPARMOR ---
echo ""
echo "--- SECTION 6: APPARMOR ---"
systemctl enable apparmor 2>/dev/null || true
systemctl start apparmor 2>/dev/null || true
if command -v aa-enforce &>/dev/null; then
    for profile in /etc/apparmor.d/*; do
        [ -f "$profile" ] || continue
        base=$(basename "$profile")
        [ -e "/etc/apparmor.d/disable/${base}" ] && continue
        [[ "$base" == *snap* ]] && continue
        aa-enforce "$profile" 2>/dev/null || true
    done
fi

# --- 7. KERNEL MODULES & SYSCTL HARDENING ---
echo ""
echo "--- SECTION 7: KERNEL MODULES & SYSCTL ---"
cat > /etc/modprobe.d/99-cyberpatriot-blacklist.conf <<EOF
# Unused filesystems (CIS Benchmark)
install cramfs /bin/false
blacklist cramfs
install freevxfs /bin/false
blacklist freevxfs
install jffs2 /bin/false
blacklist jffs2
install hfs /bin/false
blacklist hfs
install hfsplus /bin/false
blacklist hfsplus
install udf /bin/false
blacklist udf

# Rare / insecure network protocols
install dccp /bin/false
blacklist dccp
install sctp /bin/false
blacklist sctp
install rds /bin/false
blacklist rds
install tipc /bin/false
blacklist tipc

# FireWire DMA
install firewire-core /bin/false
blacklist firewire-core
install firewire-ohci /bin/false
blacklist firewire-ohci
EOF

if [[ "$DISABLE_USB_STORAGE" == true ]]; then
    cat >> /etc/modprobe.d/99-cyberpatriot-blacklist.conf <<EOF
install usb-storage /bin/false
blacklist usb-storage
EOF
    modprobe -r usb-storage 2>/dev/null || true
fi

# Kernel & Network sysctl hardening (keeps IPv6 active so APT/services work, but hardens RA/redirects)
add_or_update_sysctl "fs.suid_dumpable" "0"
add_or_update_sysctl "fs.protected_hardlinks" "1"
add_or_update_sysctl "fs.protected_symlinks" "1"
add_or_update_sysctl "fs.protected_fifos" "2"
add_or_update_sysctl "fs.protected_regular" "2"
add_or_update_sysctl "kernel.randomize_va_space" "2"
add_or_update_sysctl "kernel.kptr_restrict" "2"
add_or_update_sysctl "kernel.dmesg_restrict" "1"
add_or_update_sysctl "kernel.yama.ptrace_scope" "1"
add_or_update_sysctl "kernel.unprivileged_bpf_disabled" "1"
add_or_update_sysctl "net.core.bpf_jit_harden" "2"
add_or_update_sysctl "kernel.sysrq" "0"
add_or_update_sysctl "net.ipv4.ip_forward" "0"
add_or_update_sysctl "net.ipv4.conf.all.rp_filter" "1"
add_or_update_sysctl "net.ipv4.conf.default.rp_filter" "1"
add_or_update_sysctl "net.ipv4.conf.all.accept_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.accept_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.secure_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.secure_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.send_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.send_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.accept_source_route" "0"
add_or_update_sysctl "net.ipv4.conf.default.accept_source_route" "0"
add_or_update_sysctl "net.ipv4.conf.all.log_martians" "1"
add_or_update_sysctl "net.ipv4.conf.default.log_martians" "1"
add_or_update_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
add_or_update_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"
add_or_update_sysctl "net.ipv4.tcp_syncookies" "1"
add_or_update_sysctl "net.ipv4.tcp_rfc1337" "1"
add_or_update_sysctl "net.ipv4.tcp_max_syn_backlog" "2048"
add_or_update_sysctl "net.ipv4.tcp_synack_retries" "2"
add_or_update_sysctl "net.ipv4.tcp_syn_retries" "5"
add_or_update_sysctl "net.ipv6.conf.all.forwarding" "0"
add_or_update_sysctl "net.ipv6.conf.all.accept_ra" "0"
add_or_update_sysctl "net.ipv6.conf.default.accept_ra" "0"
add_or_update_sysctl "net.ipv6.conf.all.accept_redirects" "0"
add_or_update_sysctl "net.ipv6.conf.default.accept_redirects" "0"
add_or_update_sysctl "net.ipv6.conf.all.accept_source_route" "0"
add_or_update_sysctl "net.ipv6.conf.default.accept_source_route" "0"

sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-cyberpatriot.conf || true

if [ -f /etc/systemd/coredump.conf ]; then
    sed -i 's/^#\?Storage=.*/Storage=none/' /etc/systemd/coredump.conf
    sed -i 's/^#\?ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf
    systemctl daemon-reload 2>/dev/null || true
fi
if ! grep -qE '^\*\s+hard\s+core\s+0' /etc/security/limits.conf; then
    echo "* hard core 0" >> /etc/security/limits.conf
fi

# --- 8. PAM, PASSWORD POLICIES & USER ACCOUNT ENFORCEMENT ---
echo ""
echo "--- SECTION 8: PAM, USERS & PASSWORD POLICIES ---"
if [ ! -d /var/backups/pam.d.orig ]; then
    cp -r /etc/pam.d /var/backups/pam.d.orig
fi

passwd -l root 2>/dev/null || true

# Harden login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs
if grep -qE '^UMASK\s+' /etc/login.defs; then
    sed -i 's/^UMASK\s\+.*/UMASK\t\t027/' /etc/login.defs
else
    echo "UMASK 027" >> /etc/login.defs
fi
if grep -qE '^ENCRYPT_METHOD\s+(DES|MD5)' /etc/login.defs; then
    sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
fi

cat > /etc/security/pwquality.conf <<EOF
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 3
dictcheck = 1
usercheck = 1
enforcing = 1
enforce_for_root
EOF

cat > /etc/security/faillock.conf <<EOF
deny = 5
unlock_time = 900
silent
audit
EOF

PAM_PROFILES=("unix")
if find /lib /usr/lib -name "pam_pwquality.so" 2>/dev/null | grep -q "pam_pwquality.so" && [ -f /usr/share/pam-configs/pwquality ]; then
    PAM_PROFILES+=("pwquality")
fi
if find /lib /usr/lib -name "pam_faillock.so" 2>/dev/null | grep -q "pam_faillock.so"; then
    cat > /usr/share/pam-configs/faillock <<'EOF'
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]			pam_faillock.so authfail
EOF
    cat > /usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify of failed login attempts and reset count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite			pam_faillock.so preauth
Account-Type: Primary
Account:
	required			pam_faillock.so
EOF
    PAM_PROFILES+=("faillock" "faillock_notify")
fi

pam-auth-update --package --enable "${PAM_PROFILES[@]}" --force || echo " (!) pam-auth-update warning"

if grep -q "pam_unix.so" /etc/pam.d/common-password; then
    sed -i -E 's/(pam_unix\.so.*)\s+remember=[0-9]+/\1/g' /etc/pam.d/common-password
    sed -i 's/pam_unix\.so.*/& remember=5/' /etc/pam.d/common-password
fi
if grep -q "nullok" /etc/pam.d/common-auth; then
    sed -i 's/\snullok\b//g' /etc/pam.d/common-auth
fi

# Strip all members from nopasswdlogin & dangerous raw-access groups
for bad_grp in nopasswdlogin shadow disk root; do
    if grep -q "^${bad_grp}:" /etc/group; then
        members=$(grep "^${bad_grp}:" /etc/group | cut -d: -f4)
        if [ -n "$members" ]; then
            IFS=',' read -ra m_arr <<< "$members"
            for m in "${m_arr[@]}"; do
                [[ "$m" == "root" ]] && continue
                echo " (>) Removing $m from dangerous group $bad_grp..."
                gpasswd -d "$m" "$bad_grp" 2>/dev/null || true
            done
        fi
    fi
done

# Fix non-root UID 0 & lock/nologin any system accounts (UID < 1000) with interactive shells or unlocked passwords
while IFS=: read -r uname pw uid gid gecos home shell; do
    if [[ "$uid" -eq 0 && "$uname" != "root" ]]; then
        new_uid=$(shuf -i 2000-5000 -n 1)
        while awk -F: '{print $3}' /etc/passwd | grep -qx "$new_uid"; do
            new_uid=$(shuf -i 2000-5000 -n 1)
        done
        echo " (!!!) Non-root UID 0 detected ($uname) -> reassigned to $new_uid"
        usermod -u "$new_uid" "$uname" || true
    elif [[ "$uid" -gt 0 && "$uid" -lt 1000 && "$uname" != "sync" && "$uname" != "shutdown" && "$uname" != "halt" && "$uname" != "nobody" ]]; then
        if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" || "$shell" == "/usr/bin/bash" ]]; then
            echo " (>) Locking interactive shell on system account $uname ($shell -> /usr/sbin/nologin)"
            usermod -s /usr/sbin/nologin "$uname" 2>/dev/null || true
        fi
        pw_field=$(awk -F: -v u="$uname" '$1==u {print $2}' /etc/shadow)
        if [[ "$pw_field" != "!"* && "$pw_field" != "*"* ]]; then
            echo " (>) Locking password on system account $uname"
            usermod -L "$uname" 2>/dev/null || true
        fi
    fi
done < /etc/passwd

# Automated README User & Admin Enforcement (ONLY if AUTHORIZED_ADMINS is populated)
if [[ ${#AUTHORIZED_ADMINS[@]} -gt 0 ]]; then
    echo " (>) Enforcing README user/admin policy..."
    ALL_VALID_USERS=("${AUTHORIZED_ADMINS[@]}" "${AUTHORIZED_USERS[@]}")
    mkdir -p /var/backups/removed_users

    # Create missing authorized users & enforce sudo membership
    for req_admin in "${AUTHORIZED_ADMINS[@]}"; do
        if ! id "$req_admin" &>/dev/null; then
            echo " (+) Creating missing authorized admin: $req_admin"
            useradd -m -s /bin/bash "$req_admin"
        fi
        usermod -aG sudo "$req_admin"
    done

    for req_user in "${AUTHORIZED_USERS[@]}"; do
        if ! id "$req_user" &>/dev/null; then
            echo " (+) Creating missing authorized user: $req_user"
            useradd -m -s /bin/bash "$req_user"
        fi
    done

    # Strip unauthorized privilege-group memberships
    for priv_grp in sudo adm admin wheel lpadmin docker lxd; do
        if grep -q "^${priv_grp}:" /etc/group; then
            grp_members=$(grep "^${priv_grp}:" /etc/group | cut -d: -f4)
            if [ -n "$grp_members" ]; then
                IFS=',' read -ra g_arr <<< "$grp_members"
                for member in "${g_arr[@]}"; do
                    if ! is_in_array "$member" "${AUTHORIZED_ADMINS[@]}"; then
                        # Protect operator from losing sudo if they forgot themselves
                        if [[ "$priv_grp" == "sudo" && "$member" == "$CURRENT_OPERATOR" ]]; then
                            echo " (!) Keeping $CURRENT_OPERATOR in sudo so active session isn't locked out."
                            continue
                        fi
                        echo " (-) Removing unauthorized user $member from $priv_grp"
                        gpasswd -d "$member" "$priv_grp" 2>/dev/null || true
                    fi
                done
            fi
        fi
    done

    # Archive & remove unauthorized human accounts
    for existing_user in $(awk -F: '($3 >= 1000 && $3 < 60000) {print $1}' /etc/passwd); do
        if ! is_in_array "$existing_user" "${ALL_VALID_USERS[@]}"; then
            if [[ "$existing_user" == "$CURRENT_OPERATOR" ]]; then
                echo " (!) Skipping deletion of active operator $CURRENT_OPERATOR"
                continue
            fi
            echo " (-) Removing unauthorized user $existing_user (archiving home to /var/backups/removed_users/)..."
            pkill -KILL -u "$existing_user" 2>/dev/null || true
            if [ -d "/home/${existing_user}" ]; then
                tar -czf "/var/backups/removed_users/${existing_user}_${TIMESTAMP}.tar.gz" "/home/${existing_user}" 2>/dev/null || true
            fi
            userdel -r "$existing_user" 2>/dev/null || userdel "$existing_user" 2>/dev/null || true
        fi
    done

    # Optional bulk password rotation for all authorized users
    if [[ "$ROTATE_PASSWORDS" == true && -n "$NEW_COMP_PASSWORD" ]]; then
        for valid_user in "${ALL_VALID_USERS[@]}"; do
            if id "$valid_user" &>/dev/null; then
                echo "${valid_user}:${NEW_COMP_PASSWORD}" | chpasswd || echo " (!) Failed chpasswd for $valid_user"
            fi
        done
        echo " (>) Password rotation completed for authorized users."
    fi
fi

# Enforce aging & home directory permissions on all remaining human accounts
for user in $(awk -F: '($3 >= 1000 && $3 < 60000) {print $1}' /etc/passwd); do
    chage -M 90 -m 7 -W 14 "$user"
    if [ -d "/home/${user}" ]; then
        chown -R "${user}:${user}" "/home/${user}" 2>/dev/null || true
        chmod 750 "/home/${user}" 2>/dev/null || true
    fi
done

# --- 9. SERVICES, NETWORK FIREWALL & APPLICATION HARDENING ---
echo ""
echo "--- SECTION 9: SERVICES, FIREWALL & APP HARDENING ---"

ALWAYS_INSECURE_SERVICES=(
    "avahi-daemon" "cups" "cups-browsed" "rpcbind" "telnetd" "pure-ftpd"
    "pop3" "fingerd" "rstatd" "ruserd" "rwalld" "snmpd" "xrdp"
    "vncserver" "inetd" "openbsd-inetd" "xinetd" "postfix" "exim4" "nfs-kernel-server"
)
for service in "${ALWAYS_INSECURE_SERVICES[@]}"; do
    if systemctl is-active --quiet "$service" || systemctl is-enabled --quiet "$service" 2>/dev/null; then
        echo " (>) Stopping and disabling $service..."
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
    fi
done

# Potentially scored services: auto-disable ONLY if REQUIRED_SERVICES was supplied
SCORED_CANDIDATES=("apache2" "nginx" "vsftpd" "smbd" "nmbd" "bind9" "dovecot" "squid" "mysql" "mariadb" "postgresql" "ssh" "sshd")
if [[ ${#REQUIRED_SERVICES[@]} -gt 0 ]]; then
    for svc in "${SCORED_CANDIDATES[@]}"; do
        svc_match="$svc"
        [[ "$svc" == "sshd" ]] && svc_match="ssh"
        [[ "$svc" == "nmbd" ]] && svc_match="smbd"
        [[ "$svc" == "mariadb" ]] && svc_match="mysql"
        if ! is_in_array "$svc" "${REQUIRED_SERVICES[@]}" && ! is_in_array "$svc_match" "${REQUIRED_SERVICES[@]}"; then
            if systemctl is-active --quiet "$svc" || systemctl is-enabled --quiet "$svc" 2>/dev/null; then
                echo " (>) Stopping/disabling unrequested service: $svc"
                systemctl stop "$svc" 2>/dev/null || true
                systemctl disable "$svc" 2>/dev/null || true
            fi
        fi
    done
fi

# Protect Mint Desktop & VM Guest packages, then safely purge prohibited packages
PROTECTED_PKGS=(
    "mint-meta-cinnamon" "mint-meta-core" "cinnamon" "cinnamon-core"
    "cinnamon-desktop-environment" "nemo" "lightdm" "slick-greeter"
    "xorg" "network-manager" "network-manager-gnome" "gnome-terminal"
    "sudo" "systemd" "dkms" "open-vm-tools-desktop" "virtualbox-guest-utils"
)
for pkg in "${PROTECTED_PKGS[@]}"; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        apt-mark manual "$pkg" &>/dev/null || true
    fi
done

PROHIBITED_PACKAGES=(
    "telnet" "rsh-client" "rsh-redone-client" "rsh-server" "talk" "ypbind" "nis" "yp-tools"
    "xinetd" "openbsd-inetd" "tftpd" "tftpd-hpa" "tftp" "atftpd"
    "john" "nmap" "zenmap" "hydra" "wireshark" "tshark" "tcpdump"
    "netcat" "netcat-openbsd" "netcat-traditional" "ophcrack" "kismet" "minetest"
    "aircrack-ng" "metasploit-framework" "nikto" "sqlmap" "burpsuite" "medusa" "hashcat"
    "ettercap-common" "dsniff" "beef-xss" "maltego" "crunch" "doona"
    "teamviewer" "anydesk" "tightvncserver" "vnc4server" "x11vnc" "rdesktop"
    "steam" "steam-launcher" "minecraft-launcher" "wesnoth" "spotify-client"
    "discord" "zoom" "frozen-bubble" "snmp" "snmpd" "finger" "rlogin" "rexec"
    "wine" "wine32" "wine64"
    "aisleriot" "gnome-games" "kmines" "quadrapassel" "tali" "iagno" "lightsoff"
    "qbittorrent" "deluge" "frostwire" "nicotine"
    "skypeforlinux" "slack-desktop" "telegram-desktop"
    "transmission-gtk" "transmission-common" "hexchat" "pidgin" "vino" "warpinator"
    "amule" "zangband"
)
for pkg in "${PROHIBITED_PACKAGES[@]}"; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        SIM_OUTPUT=$(apt-get -s purge "$pkg" 2>&1)
        if echo "$SIM_OUTPUT" | grep -qE "Remv (cinnamon|mint-meta-cinnamon|mint-meta-core|lightdm|xorg|sudo|systemd|dkms|network-manager)\b"; then
            echo " (!) Skipping purge of $pkg (would remove core desktop/system dependencies)"
        else
            echo " (>) Purging prohibited package: $pkg"
            apt-get purge -y "$pkg" || true
        fi
    fi
done

# UFW Firewall Setup + Auto-Allow for Required Services
if command -v ufw &>/dev/null; then
    ufw default deny incoming
    ufw default allow outgoing
    ufw logging on

    if [[ ${#REQUIRED_SERVICES[@]} -gt 0 ]]; then
        for req_svc in "${REQUIRED_SERVICES[@]}"; do
            case "$req_svc" in
                ssh|sshd)       ufw allow 22/tcp ;;
                apache2|nginx)  ufw allow 80/tcp; ufw allow 443/tcp ;;
                vsftpd|ftp)     ufw allow 20/tcp; ufw allow 21/tcp ;;
                smbd|samba)     ufw allow Samba ;;
                bind9|dns)      ufw allow 53 ;;
                dovecot)        ufw allow 143/tcp; ufw allow 993/tcp ;;
                postfix)        ufw allow 25/tcp ;;
                mysql|mariadb)  ufw allow 3306/tcp ;;
                postgresql)     ufw allow 5432/tcp ;;
                squid)          ufw allow 3128/tcp ;;
                *)              ufw allow "$req_svc" 2>/dev/null || true ;;
            esac
        done
    elif systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        ufw allow ssh
    fi
    ufw --force enable
    ufw status verbose
fi

# --- 9.1 HARDEN OPENSSH 8.9 ---
SSH_CONFIG="/etc/ssh/sshd_config"
if [ -f "${SSH_CONFIG}" ] && command -v sshd &>/dev/null; then
    echo " (>) Hardening OpenSSH..."
    cp "${SSH_CONFIG}" "${BACKUP_DIR}/sshd_config.bak"
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"
    sed -i 's/^#\?HostbasedAuthentication.*/HostbasedAuthentication no/' "$SSH_CONFIG"
    sed -i 's/^#\?IgnoreRhosts.*/IgnoreRhosts yes/' "$SSH_CONFIG"
    sed -i 's/^#\?PermitUserEnvironment.*/PermitUserEnvironment no/' "$SSH_CONFIG"
    sed -i 's/^#\?MaxAuthTries.*/MaxAuthTries 3/' "$SSH_CONFIG"
    sed -i 's/^#\?LoginGraceTime.*/LoginGraceTime 60/' "$SSH_CONFIG"
    sed -i 's|^#\?Banner.*|Banner /etc/issue.net|' "$SSH_CONFIG"

    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-cyberpatriot.conf <<EOF
PermitRootLogin no
PermitEmptyPasswords no
PubkeyAuthentication yes
HostbasedAuthentication no
IgnoreRhosts yes
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
LoginGraceTime 60
MaxAuthTries 3
MaxSessions 4
ClientAliveInterval 300
ClientAliveCountMax 2
UsePAM yes
LogLevel VERBOSE
Banner /etc/issue.net
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256
EOF
    chmod 600 /etc/ssh/sshd_config.d/00-cyberpatriot.conf "$SSH_CONFIG"

    if sshd -t; then
        systemctl is-active --quiet ssh && systemctl restart ssh
        systemctl is-active --quiet sshd && systemctl restart sshd
    else
        echo " (!) sshd -t failed! Reverting OpenSSH hardening drop-in."
        cp "${BACKUP_DIR}/sshd_config.bak" "$SSH_CONFIG"
        rm -f /etc/ssh/sshd_config.d/00-cyberpatriot.conf
    fi
fi

# Clear unauthorized SSH authorized_keys (backup stored safely)
mkdir -p "${BACKUP_DIR}/ssh_keys"
find /home /root -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
    safe_name=$(echo "$keyfile" | tr '/' '_')
    cp "$keyfile" "${BACKUP_DIR}/ssh_keys/${safe_name}.bak"
    report_line "Cleared SSH authorized_keys: $keyfile (backed up to ${BACKUP_DIR}/ssh_keys/${safe_name}.bak)"
    : > "$keyfile"
    chmod 600 "$keyfile"
done

# --- 9.2 HARDEN VSFTPD, APACHE2, NGINX, SAMBA, MYSQL, POSTGRESQL & PHP ---
if dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q "install ok installed"; then
    echo " (>) Hardening vsftpd..."
    VSFTPD_CONF="/etc/vsftpd.conf"
    cp "$VSFTPD_CONF" "${BACKUP_DIR}/vsftpd.conf.bak"
    CERT_FILE="/etc/ssl/private/vsftpd.pem"
    mkdir -p /etc/ssl/private
    if [ ! -f "$CERT_FILE" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$CERT_FILE" -out "$CERT_FILE" \
            -subj "/C=US/ST=CyberPatriot/L=Security/O=IT/CN=ftp.secure" 2>/dev/null
        chmod 600 "$CERT_FILE"
    fi
    for key in anonymous_enable local_enable write_enable ssl_enable allow_anon_ssl \
               force_local_data_ssl force_local_logins_ssl ssl_tlsv1 ssl_sslv2 ssl_sslv3 \
               rsa_cert_file rsa_private_key_file chroot_local_user allow_writeable_chroot ssl_ciphers; do
        sed -i "/^${key}=/d" "$VSFTPD_CONF"
    done
    cat >> "$VSFTPD_CONF" <<EOF
anonymous_enable=NO
local_enable=YES
write_enable=YES
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
ssl_ciphers=HIGH
rsa_cert_file=${CERT_FILE}
rsa_private_key_file=${CERT_FILE}
chroot_local_user=YES
allow_writeable_chroot=YES
EOF
    systemctl is-active --quiet vsftpd && systemctl restart vsftpd || true
fi

if [ -d /etc/apache2 ] && command -v apache2ctl &>/dev/null; then
    echo " (>) Hardening Apache2..."
    mkdir -p /etc/apache2/conf-available
    cat > /etc/apache2/conf-available/cyberpatriot-hardening.conf <<EOF
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None

<Directory /var/www/>
    Options -Indexes +FollowSymLinks
    AllowOverride None
</Directory>

<IfModule mod_headers.c>
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "SAMEORIGIN"
</IfModule>
EOF
    a2enmod headers 2>/dev/null || true
    a2enconf cyberpatriot-hardening 2>/dev/null || true
    if apache2ctl -t 2>/dev/null; then
        systemctl is-active --quiet apache2 && systemctl restart apache2 || true
    else
        a2disconf cyberpatriot-hardening 2>/dev/null || true
        rm -f /etc/apache2/conf-available/cyberpatriot-hardening.conf
    fi
fi

if [ -d /etc/nginx ] && command -v nginx &>/dev/null; then
    echo " (>) Hardening Nginx..."
    mkdir -p /etc/nginx/conf.d
    echo "server_tokens off;" > /etc/nginx/conf.d/99-cyberpatriot.conf
    if nginx -t 2>/dev/null; then
        systemctl is-active --quiet nginx && systemctl restart nginx || true
    else
        rm -f /etc/nginx/conf.d/99-cyberpatriot.conf
    fi
fi

if [ -f /etc/samba/smb.conf ] && command -v testparm &>/dev/null; then
    echo " (>) Hardening Samba..."
    cp /etc/samba/smb.conf "${BACKUP_DIR}/smb.conf.bak"
    sed -i -E 's/^\s*(guest ok|public)\s*=.*/    guest ok = no/I' /etc/samba/smb.conf
    sed -i -E '/^\s*(server min protocol|client min protocol|map to guest|restrict anonymous|usershare allow guests)\s*=/Id' /etc/samba/smb.conf
    sed -i '/^\[global\]/a \   server min protocol = SMB2\n   client min protocol = SMB2\n   map to guest = Never\n   restrict anonymous = 2\n   usershare allow guests = no' /etc/samba/smb.conf
    if testparm -s /etc/samba/smb.conf >/dev/null 2>&1; then
        systemctl is-active --quiet smbd && systemctl restart smbd || true
    else
        cp "${BACKUP_DIR}/smb.conf.bak" /etc/samba/smb.conf
    fi
fi

if [ -d "/etc/mysql" ]; then
    echo " (>) Securing MySQL/MariaDB..."
    find /etc/mysql -name "*.cnf" -exec sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' {} \;
    systemctl is-active --quiet mysql && systemctl restart mysql || true
    systemctl is-active --quiet mariadb && systemctl restart mariadb || true
fi

if [ -d "/etc/postgresql" ]; then
    echo " (>) Checking PostgreSQL..."
    grep -rnE '^[^#].*\btrust\b' /etc/postgresql/ 2>/dev/null >> "$REPORT_FILE" || true
fi

if [ -d "/etc/php" ]; then
    echo " (>) Hardening PHP..."
    while IFS= read -r ini; do
        cp "$ini" "${BACKUP_DIR}/$(echo "$ini" | tr '/' '_').bak"
        sed -i 's/^\s*;\?\s*allow_url_fopen\s*=.*/allow_url_fopen = Off/' "$ini"
        sed -i 's/^\s*;\?\s*allow_url_include\s*=.*/allow_url_include = Off/' "$ini"
        sed -i 's/^\s*;\?\s*max_execution_time\s*=.*/max_execution_time = 30/' "$ini"
        sed -i 's/^\s*;\?\s*expose_php\s*=.*/expose_php = Off/' "$ini"
        sed -i 's/^\s*;\?\s*disable_functions\s*=.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' "$ini"
        sed -i 's/^\s*;\?\s*log_errors\s*=.*/log_errors = On/' "$ini"
    done < <(find /etc/php -name "php.ini")
    systemctl is-active --quiet apache2 && systemctl restart apache2 || true
fi

# --- 9.3 FAIL2BAN ---
if command -v fail2ban-server &>/dev/null; then
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 30m
maxretry = 5
backend = systemd

[sshd]
enabled = true
EOF
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
fi

# --- 10. DESKTOP, BROWSERS & LIGHTDM HARDENING ---
echo ""
echo "--- SECTION 10: LIGHTDM, CINNAMON & BROWSER POLICIES ---"
if [ -d /etc/lightdm ]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    cat > /etc/lightdm/lightdm.conf.d/99-cyberpatriot-hardening.conf <<EOF
[Seat:*]
allow-guest=false
greeter-allow-guest=false
greeter-hide-users=true
greeter-show-manual-login=true
autologin-guest=false
EOF
    find /etc/lightdm/ -type f -exec sed -i \
        -e 's/^autologin-user=.*/#autologin-user=/' \
        -e 's/^autologin-user-timeout=.*/#autologin-user-timeout=/' \
        -e 's/^autologin-guest=true/autologin-guest=false/' {} +
fi
if [ -f /etc/gdm3/custom.conf ]; then
    sed -i 's/AutomaticLoginEnable=true/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
    sed -i 's/^AutomaticLogin=/#AutomaticLogin=/' /etc/gdm3/custom.conf
fi

mkdir -p /etc/dconf/profile /etc/dconf/db/local.d/locks
cat > /etc/dconf/profile/user <<EOF
user-db:user
system-db:local
EOF
cat > /etc/dconf/db/local.d/00-cyberpatriot-hardening <<EOF
[org/cinnamon/desktop/screensaver]
lock-enabled=true
idle-activation-enabled=true
lock-delay=uint32 0

[org/cinnamon/settings-daemon/plugins/power]
lock-on-suspend=true

[org/cinnamon/desktop/session]
idle-delay=uint32 900

[org/cinnamon/desktop/media-handling]
automount=false
automount-open=false
EOF
cat > /etc/dconf/db/local.d/locks/00-cyberpatriot-hardening <<EOF
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/desktop/screensaver/idle-activation-enabled
/org/cinnamon/desktop/screensaver/lock-delay
/org/cinnamon/settings-daemon/plugins/power/lock-on-suspend
/org/cinnamon/desktop/session/idle-delay
/org/cinnamon/desktop/media-handling/automount
/org/cinnamon/desktop/media-handling/automount-open
EOF
dconf update 2>/dev/null || true

if [ -f /etc/default/keyboard ] && grep -q "terminate:ctrl_alt_bksp" /etc/default/keyboard; then
    sed -i 's/terminate:ctrl_alt_bksp,\?//g; s/,\+"/"/g' /etc/default/keyboard
    dpkg-reconfigure -f noninteractive keyboard-configuration 2>/dev/null || true
fi

# Firefox & Chromium/Chrome policies
mkdir -p /usr/lib/firefox/distribution /etc/firefox/policies
cat > /tmp/ff_policies.json <<EOF
{
  "policies": {
    "DisableAppUpdate": false,
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DisablePasswordReveal": true,
    "OfferToSaveLogins": false,
    "PasswordManagerEnabled": false,
    "BlockAboutConfig": true,
    "PopupBlocking": { "Default": true, "Locked": true },
    "Phishing": { "Enabled": true, "Locked": true }
  }
}
EOF
cp /tmp/ff_policies.json /usr/lib/firefox/distribution/policies.json 2>/dev/null || true
cp /tmp/ff_policies.json /etc/firefox/policies/policies.json 2>/dev/null || true
rm -f /tmp/ff_policies.json

for cdir in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed; do
    mkdir -p "$cdir"
    cat > "${cdir}/cyberpatriot.json" <<EOF
{
  "PasswordManagerEnabled": false,
  "SafeBrowsingProtectionLevel": 1,
  "DefaultPopupsSetting": 2,
  "MetricsReportingEnabled": false
}
EOF
done

# --- 11. FILESYSTEM, PERMISSIONS & HOSTS ---
echo ""
echo "--- SECTION 11: PERMISSIONS, /dev/shm & /etc/hosts ---"
if ! grep -qE '^\s*[^#].*\s/dev/shm\s' /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /dev/shm 2>/dev/null || true
fi

chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow /etc/gshadow
chown root:shadow /etc/shadow /etc/gshadow
chown root:root /root && chmod 700 /root

if [ -d "/var/www/html" ]; then
    chown -R root:root /var/www/html
    find /var/www/html -type d -exec chmod 755 {} \;
    find /var/www/html -type f -exec chmod 644 {} \;
fi

for fcfg in /etc/profile /etc/bash.bashrc /etc/environment; do
    [ -f "$fcfg" ] && chown root:root "$fcfg" && chmod 644 "$fcfg"
done
if [ -d /etc/profile.d ]; then
    chown root:root /etc/profile.d && chmod 755 /etc/profile.d
    find /etc/profile.d -type f -exec chown root:root {} \; -exec chmod 644 {} \;
fi

[ -f /etc/apt/sources.list ] && chown root:root /etc/apt/sources.list && chmod 644 /etc/apt/sources.list
[ -d /etc/apt/sources.list.d ] && chown root:root /etc/apt/sources.list.d && chmod 755 /etc/apt/sources.list.d && chmod 644 /etc/apt/sources.list.d/* 2>/dev/null || true

chmod 755 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
chown -R root:root /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

[ -f /var/log/wtmp ] && chmod 664 /var/log/wtmp && chown root:utmp /var/log/wtmp
[ -f /var/log/btmp ] && chmod 660 /var/log/btmp && chown root:utmp /var/log/btmp
[ -f /var/log/lastlog ] && chmod 664 /var/log/lastlog && chown root:utmp /var/log/lastlog

cp /etc/hosts "${BACKUP_DIR}/hosts.bak"
sed -i '/security\.ubuntu\.com/d;/archive\.ubuntu\.com/d;/packages\.linuxmint\.com/d;/archive\.canonical\.com/d' /etc/hosts
find /home -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null || true

# --- 12. FORENSICS, PERSISTENCE & MALWARE HUNT ---
echo ""
echo "--- SECTION 12: PERSISTENCE & FORENSIC AUDIT ---"

{
    echo ""
    echo "[2] ACTIVE LISTENING SOCKETS (ss -tulnp):"
    ss -tulnp 2>/dev/null || true

    echo ""
    echo "[3] NON-PACKAGE / CUSTOM SYSTEMD UNITS:"
    ls -la /etc/systemd/system/ 2>/dev/null | grep -vE "^total|wants$|^d.*\s\.\.?$" || true
    find /home -path "*/.config/systemd/user/*.service" 2>/dev/null || true

    echo ""
    echo "[4] CRON & AT JOBS:"
    grep -rnEv '^\s*(#|$)' /etc/crontab /etc/cron.d/ /var/spool/cron/crontabs/ 2>/dev/null || true
    atq 2>/dev/null || true

    echo ""
    echo "[5] LD_PRELOAD & SHELL PERSISTENCE HOOKS:"
    [ -f /etc/ld.so.preload ] && echo "CRITICAL: /etc/ld.so.preload exists!" && cat /etc/ld.so.preload
    grep -rnE "LD_PRELOAD|LD_LIBRARY_PATH|/dev/tcp/|nc -e|ncat |bash -i|alias sudo=" \
        /etc/environment /etc/profile /etc/profile.d/ /etc/bash.bashrc /root/.bashrc /home/*/.bashrc /home/*/.profile 2>/dev/null || true

    echo ""
    echo "[6] SUSPICIOUS PAM MODULES (pam_permit / pam_exec):"
    grep -rnE "pam_permit\.so|pam_exec\.so" /etc/pam.d/ 2>/dev/null || true

    echo ""
    echo "[7] NON-PACKAGE OR DANGEROUS SUID/SGID BINARIES:"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r bin; do
        if ! dpkg -S "$bin" &>/dev/null; then
            echo "UNPACKAGED SUID/SGID: $bin"
        elif echo "$bin" | grep -qE '/(bash|sh|dash|zsh|python.*|perl|ruby|find|vim|nano|less|more|cp|mv|env|nmap|nc|socat)$'; then
            echo "DANGEROUS SUID/SGID: $bin"
        fi
    done

    echo ""
    echo "[8] TAMPERED PACKAGE FILES (debsums -s):"
    if command -v debsums &>/dev/null; then
        debsums -s 2>/dev/null || true
    fi

    echo ""
    echo "[9] UNOWNED & HIDDEN /TEMP EXECUTABLES:"
    find /home /tmp /var/tmp \( -nouser -o -nogroup \) -ls 2>/dev/null || true
    find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null || true

    echo ""
    echo "[10] MEDIA & HACKING FILES IN /home:"
    find /home -type f \( -name "*.mp3" -o -name "*.mp4" -o -name "*.avi" -o -name "*.mkv" -o -name "*.mov" -o -name "*.wav" \
        -o -name "*.pcap" -o -name "*.pcapng" -o -name "*.john" -o -name "john" -o -name "hydra" \) 2>/dev/null || true

    echo ""
    echo "[11] ROOTKIT QUICK CHECK (chkrootkit -q):"
    if command -v chkrootkit &>/dev/null; then
        chkrootkit -q 2>/dev/null | grep -v "nothing found" || true
    fi

    echo ""
    echo "[12] CURRENT ACCOUNTS & PRIVILEGED GROUPS:"
    echo "sudo group: $(grep -Po '^sudo:.*:\K.*$' /etc/group || true)"
    echo "Human users (UID >= 1000):"
    awk -F: '($3 >= 1000 && $3 < 60000) {print "  " $1 " (UID " $3 ")"}' /etc/passwd
    echo "Empty password accounts:"
    awk -F: '($2 == "") {print "  CRITICAL NO PASSWORD: " $1}' /etc/shadow
    pwck -r 2>&1 || true
    grpck -r 2>&1 || true
} >> "$REPORT_FILE"

if [[ "$RUN_CLAMSCAN" == true ]] && command -v clamscan &>/dev/null; then
    echo " (>) Running ClamAV malware scan on /home, /tmp, /var/tmp, /var/www..."
    clamscan -r -i /home /tmp /var/tmp /var/www 2>/dev/null | tee -a "$REPORT_FILE" || true
fi

apt-get clean

echo ""
echo "=================================================================="
echo "  HARDENING COMPLETE! ACTION REPORT SAVED TO:"
echo "  ${REPORT_FILE}"
echo "=================================================================="
cat "$REPORT_FILE"

# --- 13. AIDE BASELINE AT THE VERY END (SO OPERATOR IS NEVER BLOCKED) ---
if [[ "$SKIP_AIDE" == false ]] && command -v aideinit &>/dev/null; then
    if [ ! -f /var/lib/aide/aide.db.gz ] && [ ! -f /var/lib/aide/aide.db ]; then
        echo ""
        echo " (>) Building AIDE baseline database (you may open a second terminal now)..."
        aideinit -y -f || echo " (!) aideinit warning"
        [ -f /var/lib/aide/aide.db.new ] && [ ! -f /var/lib/aide/aide.db ] && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        [ -f /var/lib/aide/aide.db.new.gz ] && [ ! -f /var/lib/aide/aide.db.gz ] && cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    fi
fi

echo ""
echo "FINAL CHECK: Run 'sudo -v' in a new terminal before rebooting!"
exit 0
