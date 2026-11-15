#!/bin/bash

# --- LINUX MINT 21 (UBUNTU 22.04 BASE) HARDENING SCRIPT FOR CYBERPATRIOT ---

set -o pipefail
export DEBIAN_FRONTEND=noninteractive

LOG_FILE="/var/log/cyberpatriot_hardening_$(date +%Y%m%d_%H%M%S).log"
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "--- CyberPatriot Linux Mint 21 Hardening Script ---"
echo "Starting system hardening at $(date)"
echo "Log file: ${LOG_FILE}"

# --- CHECK FOR ROOT PRIVILEGES ---
if [[ "${EUID}" -ne 0 ]]; then
  echo " (!) This script must be run as root. Exiting."
  exit 1
fi

# --- HELPER FUNCTIONS ---
add_or_update_sysctl() {
  local key="$1"
  local value="$2"
  local config_file="/etc/sysctl.d/99-cyberpatriot.conf"
  local escaped_key="${key//./\\.}"

  echo " (>) Configuring sysctl: ${key} = ${value}"
  touch "${config_file}"
  if grep -qE "^\s*#?\s*${escaped_key}\s*=" "${config_file}"; then
    sed -i -e "s|^\s*#*\s*${escaped_key}\s*=.*|${key} = ${value}|g" "${config_file}"
  else
    echo "${key} = ${value}" >> "${config_file}"
  fi

  # Also update /etc/sysctl.conf if key already exists there to avoid conflicts
  if [ -f /etc/sysctl.conf ] && grep -qE "^\s*#?\s*${escaped_key}\s*=" /etc/sysctl.conf; then
    sed -i -e "s|^\s*#*\s*${escaped_key}\s*=.*|${key} = ${value}|g" /etc/sysctl.conf
  fi
}

service_exists() {
  systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -qx "${1}.service"
}

# --- 1. SYSTEM UPDATES & ESSENTIAL TOOLS ---
echo ""
echo "--- SECTION 1: SYSTEM UPDATES & ESSENTIAL TOOLS ---"
if apt-get update -y; then
    echo " (>) Upgrading installed packages safely..."
    apt-get upgrade -y \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" || echo " (!) apt-get upgrade encountered an issue."

    echo " (>) Installing essential security tools..."
    # Fixed package names for Mint 21 / Ubuntu 22.04 (clamav-freshclam, libopenscap8, openscap-utils)
    SEC_PACKAGES=(
        ufw clamav clamav-daemon clamav-freshclam
        auditd audispd-plugins debsums
        libpam-pwquality libpam-apparmor apparmor-utils
        unattended-upgrades fail2ban libopenscap8 openscap-utils lynis
    )

    for pkg in "${SEC_PACKAGES[@]}"; do
        if apt-cache show "$pkg" &>/dev/null; then
            apt-get install -y --no-install-recommends "$pkg" || echo " (!) Failed to install $pkg"
        else
            echo " (!) Package $pkg not available in repos, skipping."
        fi
    done

    # Install aide separately with --no-install-recommends to avoid pulling in postfix unnecessarily
    for pkg in aide aide-common; do
        if apt-cache show "$pkg" &>/dev/null; then
            apt-get install -y --no-install-recommends "$pkg" || echo " (!) Failed to install $pkg"
        fi
    done
else
    echo " (!) apt-get update failed (offline or broken sources). Skipping updates & installs."
fi

# --- 2. ACCOUNT INACTIVITY, TMOUT, STICKY BITS & CLAMAV ---
echo ""
echo "--- SECTION 2: SHELL TIMEOUT, STICKY BITS & ANTIVIRUS ---"
echo " (>) Setting default account inactivity to 30 days..."
useradd -D -f 30

echo " (>) Setting global shell timeout (900 seconds) safely in /etc/profile.d..."
# Remove any unguarded readonly TMOUT from /etc/profile that can crash Xsession on double-source
if [ -f /etc/profile ]; then
    sed -i '/^readonly TMOUT=/d;/^export TMOUT$/d' /etc/profile
fi
mkdir -p /etc/profile.d
cat > /etc/profile.d/99-tmout.sh <<'EOF'
# Idle shell timeout (guarded so re-sourcing never crashes on readonly variable)
if [ -z "${TMOUT:-}" ]; then
    TMOUT=900
    readonly TMOUT
    export TMOUT
fi
EOF
chmod 644 /etc/profile.d/99-tmout.sh

echo " (>) Enforcing sticky bits on world-writable directories..."
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -exec chmod +t {} + 2>/dev/null || true

if command -v freshclam &>/dev/null; then
    echo " (>) Updating ClamAV virus definitions..."
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam || echo " (!) Freshclam failed (possibly offline or mirror rate-limit)."
    systemctl enable clamav-freshclam 2>/dev/null || true
    systemctl start clamav-freshclam 2>/dev/null || true

    if ls /var/lib/clamav/*.c[vl]d &>/dev/null; then
        systemctl enable clamav-daemon 2>/dev/null || true
        systemctl start clamav-daemon 2>/dev/null || echo " (!) Failed to start clamav-daemon"
    else
        echo " (!) No ClamAV database files found yet; skipping clamav-daemon start."
    fi
fi

# --- 3. AUDITING (AUDITD) & SUDOERS ---
echo ""
echo "--- SECTION 3: AUDITING (AUDITD) & SUDOERS ---"
if [ -d /etc/audit ]; then
    echo " (>) Configuring auditd..."
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.bak 2>/dev/null || true

    sed -i 's/^max_log_file_action.*/max_log_file_action = ROTATE/' /etc/audit/auditd.conf
    sed -i 's/^space_left_action.*/space_left_action = SYSLOG/' /etc/audit/auditd.conf
    sed -i 's/^admin_space_left_action.*/admin_space_left_action = SUSPEND/' /etc/audit/auditd.conf

    echo " (>) Writing rules to /etc/audit/rules.d/99-cyberpatriot.rules..."
    mkdir -p /etc/audit/rules.d
    cat > /etc/audit/rules.d/99-cyberpatriot.rules <<EOF
-D
-b 8192
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-e 2
EOF

    systemctl enable auditd 2>/dev/null || true
    systemctl start auditd 2>/dev/null || true

    if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
        echo " (*) Audit subsystem is already in immutable mode (-e 2). Reboot required to load new rules."
    else
        augenrules --load || echo " (!) augenrules --load encountered an error"
    fi
fi

echo " (>) Hardening Sudoers policy..."
cat > /etc/sudoers.d/99-cyberpatriot <<EOF
Defaults        env_reset
Defaults        mail_badpass
Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults        use_pty
Defaults        timestamp_timeout=15
EOF
chmod 440 /etc/sudoers.d/99-cyberpatriot
if ! visudo -cf /etc/sudoers.d/99-cyberpatriot; then
    echo " (!) Invalid sudoers drop-in detected! Removing to prevent sudo lockout."
    rm -f /etc/sudoers.d/99-cyberpatriot
fi

# --- 4. APPLICATION ARMOR (APPARMOR) ---
echo ""
echo "--- SECTION 4: APPLICATION ARMOR (APPARMOR) ---"
systemctl enable apparmor 2>/dev/null || true
systemctl start apparmor 2>/dev/null || true
if command -v aa-enforce &>/dev/null; then
    echo " (>) Enforcing active AppArmor profiles (skipping disabled/snap profiles)..."
    for profile in /etc/apparmor.d/*; do
        [ -f "$profile" ] || continue
        base=$(basename "$profile")
        [ -e "/etc/apparmor.d/disable/${base}" ] && continue
        [[ "$base" == *snap* ]] && continue
        aa-enforce "$profile" 2>/dev/null || true
    done
fi

# --- 5. UNATTENDED UPGRADES ---
echo ""
echo "--- SECTION 5: UNATTENDED UPGRADES ---"
mkdir -p /etc/apt/apt.conf.d
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
systemctl enable unattended-upgrades 2>/dev/null || true
systemctl start unattended-upgrades 2>/dev/null || true
echo " (i) Unattended upgrades configured."

# --- 6. FIREWALL (UFW) ---
echo ""
echo "--- SECTION 6: FIREWALL (UFW) ---"
if command -v ufw &>/dev/null; then
    ufw default deny incoming
    ufw default allow outgoing
    if systemctl is-active --quiet ssh || systemctl is-active --quiet sshd; then
        ufw allow ssh 2>/dev/null || true
    fi
    echo " (>) Enabling UFW..."
    ufw --force enable
    ufw status verbose
    echo " [!] REMINDER: If your CyberPatriot README requires services (e.g. HTTP/FTP/Samba), run 'ufw allow <port/service>'!"
else
    echo " (!) ufw not installed, skipping firewall setup."
fi

# --- 7. DISABLE INSECURE SERVICES & SAFELY PURGE PROHIBITED PACKAGES ---
echo ""
echo "--- SECTION 7: INSECURE SERVICES & PROHIBITED PACKAGES ---"

# Always-insecure / legacy services (safe to stop/disable on Mint workstations)
INSECURE_SERVICES=(
    "avahi-daemon" "cups" "rpcbind" "telnetd" "pure-ftpd"
    "pop3" "fingerd" "rstatd" "ruserd" "rwalld"
    "snmpd" "xrdp" "vncserver" "inetd" "openbsd-inetd" "xinetd"
    "postfix" "exim4" "nfs-kernel-server"
)

for service in "${INSECURE_SERVICES[@]}"; do
    if systemctl is-active --quiet "$service" || systemctl is-enabled --quiet "$service" 2>/dev/null; then
        echo " (>) Stopping and disabling $service..."
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
    fi
done

# Potentially scored services: alert clearly instead of blindly breaking README requirements
SCORED_CANDIDATES=("apache2" "nginx" "vsftpd" "smbd" "nmbd" "bind9" "dovecot" "squid" "mysql" "mariadb" "ssh")
for svc in "${SCORED_CANDIDATES[@]}"; do
    if systemctl is-active --quiet "$svc"; then
        echo " [!] ACTIVE SERVICE DETECTED: $svc (Disable manually if NOT authorized in README!)"
    fi
done

# Protect core Mint Cinnamon desktop & VM guest packages from accidental dependency removal
echo " (>) Protecting core Mint 21 desktop and VM packages..."
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

# Fixed capitalization (amule, zangband) and removed gcc/make/git/vlc (gcc/make break dkms; vlc can pull mint-meta-codecs)
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

echo " (>) Checking and safely purging installed prohibited packages..."
for pkg in "${PROHIBITED_PACKAGES[@]}"; do
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        # Simulate purge first to ensure Mint desktop / sudo / VM tools won't be removed
        SIM_OUTPUT=$(apt-get -s purge "$pkg" 2>&1)
        if echo "$SIM_OUTPUT" | grep -qE "Remv (cinnamon|mint-meta-cinnamon|mint-meta-core|lightdm|xorg|sudo|systemd|dkms|network-manager)\b"; then
            echo " (!) Skipping purge of $pkg because it would remove critical desktop/system packages!"
        else
            echo " (>) Purging $pkg..."
            apt-get purge -y "$pkg" || echo " (!) Failed to purge $pkg"
        fi
    fi
done

# --- MYSQL HARDENING ---
if [ -d "/etc/mysql" ]; then
    echo " (>) Securing MySQL/MariaDB..."
    find /etc/mysql -name "*.cnf" -exec sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' {} \;
    # Removed deprecated/duplicate skip-symbolic-links injection (unsafe on MySQL 8.x)
    if systemctl is-active --quiet mysql; then
        systemctl restart mysql || true
    elif systemctl is-active --quiet mariadb; then
        systemctl restart mariadb || true
    fi
fi

# --- SECTION 7.1: SECURE VSFTPD (FTP WITH SSL) ---
echo ""
echo "--- SECTION 7.1: SECURING VSFTPD (IF INSTALLED) ---"
if dpkg-query -W -f='${Status}' vsftpd 2>/dev/null | grep -q "install ok installed"; then
    echo " (>) vsftpd detected. Securing configuration..."
    VSFTPD_CONF="/etc/vsftpd.conf"
    cp "$VSFTPD_CONF" "${VSFTPD_CONF}.bak"

    CERT_FILE="/etc/ssl/private/vsftpd.pem"
    mkdir -p /etc/ssl/private
    if [ ! -f "$CERT_FILE" ]; then
        echo " (>) Generating self-signed SSL certificate for FTP..."
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

    for dir in /srv/ftp /var/ftp; do
        if [ -d "$dir" ]; then
            chown root:root "$dir"
            chmod 755 "$dir"
        fi
    done

    if systemctl is-active --quiet vsftpd; then
        echo " (>) Restarting active vsftpd..."
        systemctl restart vsftpd || echo " (!) Failed to restart vsftpd."
    fi
else
    echo " (*) vsftpd is not installed. Skipping."
fi

# --- PHP SECURITY HARDENING ---
if [ -d "/etc/php" ]; then
    echo " (>) Hardening PHP configuration..."
    while IFS= read -r ini; do
        echo "     - Editing $ini"
        cp "$ini" "${ini}.bak"
        sed -i 's/^\s*;\?\s*allow_url_fopen\s*=.*/allow_url_fopen = Off/' "$ini"
        sed -i 's/^\s*;\?\s*allow_url_include\s*=.*/allow_url_include = Off/' "$ini"
        sed -i 's/^\s*;\?\s*max_execution_time\s*=.*/max_execution_time = 30/' "$ini"
        sed -i 's/^\s*;\?\s*expose_php\s*=.*/expose_php = Off/' "$ini"
        sed -i 's/^\s*;\?\s*disable_functions\s*=.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' "$ini"
        sed -i 's/^\s*;\?\s*log_errors\s*=.*/log_errors = On/' "$ini"
    done < <(find /etc/php -name "php.ini")

    if systemctl is-active --quiet apache2; then
        systemctl restart apache2 || true
    fi
fi

# --- 8. SSH CONFIGURATION ---
echo ""
echo "--- SECTION 8: SECURE SSH CONFIGURATION ---"
SSH_CONFIG="/etc/ssh/sshd_config"
if [ -f "${SSH_CONFIG}" ] && command -v sshd &>/dev/null; then
    cp "${SSH_CONFIG}" "${SSH_CONFIG}.bak"
    echo "Authorized uses only." > /etc/issue.net

    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    sed -i 's/^#\?X11Forwarding.*/X11Forwarding no/' "$SSH_CONFIG"
    sed -i 's|^#\?Banner.*|Banner /etc/issue.net|' "$SSH_CONFIG"

    # Drop-in ensures first-match precedence on Ubuntu 22.04 / Mint 21
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-cyberpatriot.conf <<EOF
PermitRootLogin no
PermitEmptyPasswords no
X11Forwarding no
Banner /etc/issue.net
EOF
    chmod 600 /etc/ssh/sshd_config.d/00-cyberpatriot.conf

    if sshd -t; then
        if systemctl is-active --quiet ssh; then
            systemctl restart ssh
        elif systemctl is-active --quiet sshd; then
            systemctl restart sshd
        fi
    else
        echo " (!) SSH Config check failed. Reverting..."
        cp "${SSH_CONFIG}.bak" "${SSH_CONFIG}"
        rm -f /etc/ssh/sshd_config.d/00-cyberpatriot.conf
    fi
fi

echo " (>) Scanning for unauthorized SSH authorized_keys files..."
mkdir -p /var/backups/cyberpatriot_ssh
find /home /root -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
    echo " [!] Found SSH Authorized Key file: $keyfile"
    cat "$keyfile"
    safe_name=$(echo "$keyfile" | tr '/' '_')
    cp "$keyfile" "/var/backups/cyberpatriot_ssh/${safe_name}.bak"
    : > "$keyfile"
    chmod 600 "$keyfile"
    echo "     - Cleared contents of $keyfile (backup saved in /var/backups/cyberpatriot_ssh/)"
done

# --- 9. FAIL2BAN ---
echo ""
echo "--- SECTION 9: FAIL2BAN ---"
if command -v fail2ban-server &>/dev/null; then
    JAIL_LOCAL="/etc/fail2ban/jail.local"
    cat > "${JAIL_LOCAL}" <<EOF
[DEFAULT]
bantime = 1h
findtime = 30m
maxretry = 5
backend = systemd

[sshd]
enabled = true
EOF
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban || echo " (!) Fail2ban failed to restart"
fi

# --- 10. USER ACCOUNTS & PAM POLICIES ---
echo ""
echo "--- SECTION 10: USER ACCOUNTS & PASSWORD POLICIES ---"
cp -r /etc/pam.d /var/backups/pam.d.bak 2>/dev/null || true

passwd -l root 2>/dev/null || true

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 14/' /etc/login.defs

cat > /etc/security/pwquality.conf <<EOF
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 3
EOF

cat > /etc/security/faillock.conf <<EOF
deny = 5
unlock_time = 900
silent
audit
EOF

# Register proper pam-auth-update profiles for faillock on Ubuntu 22.04 / Mint 21
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

echo " (>) Updating PAM stack via pam-auth-update (${PAM_PROFILES[*]})..."
pam-auth-update --package --enable "${PAM_PROFILES[@]}" --force || echo " (!) pam-auth-update warning"

# Apply remember=5 and strip nullok AFTER pam-auth-update so pam-auth-update doesn't overwrite or refuse
echo " (>) Enforcing password history (remember=5) and removing nullok..."
if grep -q "pam_unix.so" /etc/pam.d/common-password; then
    sed -i -E 's/(pam_unix\.so.*)\s+remember=[0-9]+/\1/g' /etc/pam.d/common-password
    sed -i 's/pam_unix\.so.*/& remember=5/' /etc/pam.d/common-password
fi
if grep -q "nullok" /etc/pam.d/common-auth; then
    sed -i 's/\snullok\b//g' /etc/pam.d/common-auth
fi

echo " (>) Enforcing password expiration rules on all existing human users..."
for user in $(awk -F: '($3 >= 1000 && $3 < 60000) {print $1}' /etc/passwd); do
    chage -M 90 -m 7 -W 14 "$user"
    echo "     - Password aging updated for user: $user"
done

# --- FIX NOPASSWDLOGIN GROUP ---
echo " (>) Checking for users in 'nopasswdlogin' group..."
if grep -q "^nopasswdlogin:" /etc/group; then
    BAD_USERS=$(grep "^nopasswdlogin:" /etc/group | cut -d: -f4)
    if [ -n "$BAD_USERS" ]; then
        echo " (!) FOUND USERS IN nopasswdlogin: $BAD_USERS"
        IFS=',' read -ra ADDR <<< "$BAD_USERS"
        for user in "${ADDR[@]}"; do
            echo "     - Removing $user from nopasswdlogin..."
            gpasswd -d "$user" nopasswdlogin
        done
    else
        echo " (*) No users found in nopasswdlogin group."
    fi
fi

# --- SECTION 10.1: FIREFOX SECURITY ---
echo " (>) Applying Firefox Security Policies..."
mkdir -p /usr/lib/firefox/distribution /etc/firefox/policies
cat > /tmp/policies.json <<EOF
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
    "PopupBlocking": {
      "Default": true,
      "Locked": true
    },
    "Phishing": {
      "Enabled": true,
      "Locked": true
    }
  }
}
EOF
cp /tmp/policies.json /usr/lib/firefox/distribution/policies.json 2>/dev/null || true
cp /tmp/policies.json /etc/firefox/policies/policies.json 2>/dev/null || true
rm -f /tmp/policies.json

# --- CHECK FOR NON-ROOT UID 0 ---
echo " (>) Checking for non-root users with UID 0..."
UID0_USERS=$(awk -F: '($3 == "0") {print $1}' /etc/passwd)
for user in $UID0_USERS; do
    if [ "$user" != "root" ]; then
        new_uid=$(shuf -i 2000-5000 -n 1)
        while awk -F: '{print $3}' /etc/passwd | grep -qx "$new_uid"; do
            new_uid=$(shuf -i 2000-5000 -n 1)
        done
        echo " (!!!) SECURITY ALERT: User $user has UID 0! Changing to UID $new_uid..."
        usermod -u "$new_uid" "$user" || echo " (!) Could not change UID for $user (check if logged in)."
    fi
done

# --- 11. LIGHTDM & GDM3 ---
echo ""
echo "--- SECTION 11: LIGHTDM & AUTOLOGIN ---"
if [ -d /etc/lightdm ]; then
    mkdir -p /etc/lightdm/lightdm.conf.d
    # MUST include greeter-show-manual-login=true when hiding user list in Mint slick-greeter!
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

# --- SECTION 11.1: SECURE CINNAMON DESKTOP (MINT) ---
echo " (>) Configuring Cinnamon Screensaver & Lock Policies..."
mkdir -p /etc/dconf/profile /etc/dconf/db/local.d/locks
if [ ! -f /etc/dconf/profile/user ]; then
    cat > /etc/dconf/profile/user <<EOF
user-db:user
system-db:local
EOF
fi

# Fixed schema keys and uint32 GVariant types for Cinnamon
cat > /etc/dconf/db/local.d/00-cyberpatriot-hardening <<EOF
[org/cinnamon/desktop/screensaver]
lock-enabled=true
idle-activation-enabled=true
lock-delay=uint32 0

[org/cinnamon/settings-daemon/plugins/power]
lock-on-suspend=true

[org/cinnamon/desktop/session]
idle-delay=uint32 900
EOF

cat > /etc/dconf/db/local.d/locks/00-cyberpatriot-hardening <<EOF
/org/cinnamon/desktop/screensaver/lock-enabled
/org/cinnamon/desktop/screensaver/idle-activation-enabled
/org/cinnamon/desktop/screensaver/lock-delay
/org/cinnamon/settings-daemon/plugins/power/lock-on-suspend
/org/cinnamon/desktop/session/idle-delay
EOF

dconf update 2>/dev/null || true

# --- DISABLE CTRL+ALT+BACKSPACE WITHOUT WIPING KEYBOARD LAYOUTS ---
localedef -v -c -i en_US -f UTF-8 en_US.UTF-8 2>/dev/null || true
if [ -f /etc/default/keyboard ] && grep -q "terminate:ctrl_alt_bksp" /etc/default/keyboard; then
    sed -i 's/terminate:ctrl_alt_bksp,\?//g; s/,\+"/"/g' /etc/default/keyboard
    dpkg-reconfigure -f noninteractive keyboard-configuration 2>/dev/null || true
fi

# --- 12. KERNEL PARAMETERS & COREDUMPS ---
echo ""
echo "--- SECTION 12: KERNEL PARAMETERS ---"
add_or_update_sysctl "fs.suid_dumpable" "0"
add_or_update_sysctl "net.ipv4.conf.all.rp_filter" "1"
add_or_update_sysctl "net.ipv4.conf.default.rp_filter" "1"
add_or_update_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"
add_or_update_sysctl "net.ipv4.ip_forward" "0"
add_or_update_sysctl "net.ipv4.conf.all.accept_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.log_martians" "1"
add_or_update_sysctl "net.ipv4.tcp_syncookies" "1"
add_or_update_sysctl "kernel.randomize_va_space" "2"
add_or_update_sysctl "net.ipv4.conf.all.send_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.send_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.accept_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.secure_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.default.secure_redirects" "0"
add_or_update_sysctl "net.ipv4.conf.all.accept_source_route" "0"
add_or_update_sysctl "net.ipv4.conf.default.accept_source_route" "0"
add_or_update_sysctl "net.ipv4.conf.default.log_martians" "1"
add_or_update_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"
add_or_update_sysctl "net.ipv4.tcp_max_syn_backlog" "2048"
add_or_update_sysctl "net.ipv4.tcp_synack_retries" "2"
add_or_update_sysctl "net.ipv4.tcp_syn_retries" "5"

echo " (>) Applying sysctl changes..."
sysctl --system >/dev/null 2>&1 || sysctl -p /etc/sysctl.d/99-cyberpatriot.conf || true

if [ -f /etc/systemd/coredump.conf ]; then
    echo " (>) Disabling systemd core dumps..."
    sed -i 's/^#\?Storage=.*/Storage=none/' /etc/systemd/coredump.conf
    sed -i 's/^#\?ProcessSizeMax=.*/ProcessSizeMax=0/' /etc/systemd/coredump.conf
    systemctl daemon-reload 2>/dev/null || true
fi

if ! grep -qE '^\*\s+hard\s+core\s+0' /etc/security/limits.conf; then
    echo "* hard core 0" >> /etc/security/limits.conf
fi

# --- 13. SECURE SHARED MEMORY ---
if ! grep -qE '^\s*[^#].*\s/dev/shm\s' /etc/fstab; then
    echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev 0 0" >> /etc/fstab
    mount -o remount /dev/shm 2>/dev/null || true
fi

# --- 14. PERMISSIONS & CONFIG CLEANUP ---
echo ""
echo "--- SECTION 14: FILE PERMISSIONS & CLEANUP ---"
chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow /etc/gshadow
chown root:shadow /etc/shadow /etc/gshadow
chmod 600 /etc/ssh/sshd_config 2>/dev/null || true

if [ -d "/var/www/html" ]; then
    echo " (>) Securing /var/www/html permissions..."
    chown -R root:root /var/www/html
    find /var/www/html -type d -exec chmod 755 {} \;
    find /var/www/html -type f -exec chmod 644 {} \;
fi

chown root:root /root
chmod 700 /root

# Fixed: /etc/profile.d MUST be 755 (directory), while files inside it are 644!
for file_cfg in /etc/profile /etc/bash.bashrc /etc/environment; do
    if [ -f "$file_cfg" ]; then
        chown root:root "$file_cfg"
        chmod 644 "$file_cfg"
    fi
done
if [ -d /etc/profile.d ]; then
    chown root:root /etc/profile.d
    chmod 755 /etc/profile.d
    find /etc/profile.d -type f -exec chown root:root {} \; -exec chmod 644 {} \;
fi

if [ -d /etc/sudoers.d ]; then
    chmod 755 /etc/sudoers.d
    chmod 440 /etc/sudoers.d/* 2>/dev/null || true
fi

if [ -f /etc/apt/sources.list ]; then
    chown root:root /etc/apt/sources.list
    chmod 644 /etc/apt/sources.list
fi
if [ -d /etc/apt/sources.list.d ]; then
    chown root:root /etc/apt/sources.list.d
    chmod 755 /etc/apt/sources.list.d
    chmod 644 /etc/apt/sources.list.d/* 2>/dev/null || true
fi

chmod 755 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
chown -R root:root /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly 2>/dev/null || true
chmod 600 /etc/crontab 2>/dev/null || true

[ -f /var/log/wtmp ] && chmod 664 /var/log/wtmp && chown root:utmp /var/log/wtmp
[ -f /var/log/btmp ] && chmod 660 /var/log/btmp && chown root:utmp /var/log/btmp
[ -f /var/log/lastlog ] && chmod 664 /var/log/lastlog && chown root:utmp /var/log/lastlog

echo " (>) Checking /etc/hosts for malicious repository redirects..."
cp /etc/hosts /etc/hosts.bak
sed -i '/security\.ubuntu\.com/d;/archive\.ubuntu\.com/d;/packages\.linuxmint\.com/d;/archive\.canonical\.com/d' /etc/hosts

echo " (>) Checking sudoers for NOPASSWD / !authenticate entries..."
cp /etc/sudoers /etc/sudoers.bak
if grep -qE '^[^#]*(NOPASSWD|!authenticate)' /etc/sudoers; then
    sed -i -E 's/^([^#]*(NOPASSWD|!authenticate).*)/# \1/' /etc/sudoers
    echo "     - Commented out NOPASSWD/!authenticate in /etc/sudoers"
fi
if [ -d /etc/sudoers.d ]; then
    grep -rlE '^[^#]*(NOPASSWD|!authenticate)' /etc/sudoers.d/ 2>/dev/null | while read -r file; do
        sed -i -E 's/^([^#]*(NOPASSWD|!authenticate).*)/# \1/' "$file"
        echo "     - Commented out NOPASSWD/!authenticate in $file"
    done
fi
if ! visudo -c; then
    echo " (!) visudo check failed! Restoring /etc/sudoers backup."
    cp /etc/sudoers.bak /etc/sudoers
fi

echo " (>) Removing world-writable permissions on files in /home..."
find /home -type f -perm -0002 -exec chmod o-w {} + 2>/dev/null || true

# --- 15. INITIALIZE AIDE AFTER HARDENING ---
echo ""
echo "--- SECTION 15: FILE INTEGRITY CHECKER (AIDE) ---"
if command -v aideinit &>/dev/null; then
    if [ ! -f /var/lib/aide/aide.db.gz ] && [ ! -f /var/lib/aide/aide.db ]; then
        echo " (>) Initializing AIDE baseline database (this may take several minutes)..."
        aideinit -y -f || echo " (!) aideinit failed."
        if [ -f /var/lib/aide/aide.db.new ] && [ ! -f /var/lib/aide/aide.db ]; then
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        elif [ -f /var/lib/aide/aide.db.new.gz ] && [ ! -f /var/lib/aide/aide.db.gz ]; then
            cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
        fi
    else
        echo " (*) AIDE database already exists."
    fi
fi

# --- 16. PROHIBITED FILES & PERSISTENCE AUDIT ---
echo ""
echo "--- SECTION 16: PROHIBITED FILES & PERSISTENCE AUDIT ---"
echo " (i) Searching /home for media files..."
find /home -type f \( -name "*.mp3" -o -name "*.mp4" -o -name "*.avi" -o -name "*.mkv" -o -name "*.mov" -o -name "*.wav" \) -print 2>/dev/null

echo " (i) Searching /home for hacking tools/captures..."
find /home -type f \( -name "*.pcap" -o -name "*.pcapng" -o -name "john" -o -name "hydra" \) -print 2>/dev/null

echo " (>) Checking for unowned files..."
find /home /tmp /var/tmp \( -nouser -o -nogroup \) -exec ls -l {} + 2>/dev/null

echo " (>) Checking for suspicious startup/cron files..."
ls -la /etc/init.d/ | grep -v "root" || true
ls -la /etc/rc.local 2>/dev/null || true
find /etc/cron* /var/spool/cron -name ".*" -print 2>/dev/null || true

apt-get clean

echo ""
echo "=================================================="
echo "   CURRENT USER AUDIT (COMPARE WITH README!)"
echo "=================================================="
echo "ADMINS (sudo group):"
grep -Po '^sudo:.*:\K.*$' /etc/group || true
echo "--------------------------------------------------"
echo "ALL USERS (UID >= 1000):"
awk -F: '($3 >= 1000 && $3 < 60000) {print $1, $3}' /etc/passwd
echo "=================================================="

for name in backdoor hacker attacker shadow temp test root2 admin2; do
    if id "$name" &>/dev/null; then
        echo " [!!!] SUSPICIOUS USER FOUND: $name. Check README immediately!"
    fi
done

EMPTY_PW=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
for user in $EMPTY_PW; do
    echo " [!] Account $user has NO PASSWORD!"
done

pwck -r || echo " [!!!] Potential issues found in /etc/passwd or /etc/shadow!"
grpck -r || echo " [!!!] Potential issues found in /etc/group or /etc/gshadow!"

echo "--- CRON JOB AUDIT ---"
for user in $(awk -F: '{print $1}' /etc/passwd); do
    crontab -u "$user" -l 2>/dev/null | grep -vE '^(#|$)' && echo " (!!!) Above cron job found for user: $user"
done

echo ""
echo "Hardening complete. Test 'sudo -v' and verify user passwords before rebooting!"
exit 0
