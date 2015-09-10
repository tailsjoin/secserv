#!/bin/bash
set -e
clear
echo ""
if [[ $(id -u) != "0" ]]; then
  echo -e "\n\nYou need to be root or sudo!\n"
  read -p "Press enter to exit. "
  exit 0
fi


# Config/harden SSH.
read -p "(R)andom ssh port or (U)ser defined? (r/u)? " ru
if [[ "$ru" = "r" || "$ru" = "R" ]]; then
  sshport=$(((1000+$RANDOM%60000)+(1000+$RANDOM%40000)))
  while [[ "$sshport" -gt "9000" && "$sshport" -lt "10000" ]]; do
    sshport=$(((1000+$RANDOM%60000)+(1000+$RANDOM%40000)))
  done
else
  echo ""
  read -p "What ssh port? " sshport
  while [[ "$sshport" != @(-|)[0-9]*([0-9]) ]]; do
    clear
    echo -e "\n\nEnter an integer please.\n"
    read -p "What ssh port? " sshport
  done
fi

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
echo "Port "$sshport"
Protocol 2
DebianBanner no
Banner /etc/issue.net
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 4096
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 30
PermitRootLogin without-password
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile      %h/.ssh/authorized_keys
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM no" > /etc/ssh/sshd_config

cp /etc/ssh/ssh_config /etc/ssh/ssh_config.bak
echo "Host *
    KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
    PubkeyAuthentication yes
    HostKeyAlgorithms ssh-ed25519-cert-v01@openssh.com,ssh-rsa-cert-v01@openssh.com,ssh-rsa-cert-v00@openssh.com,ssh-ed25519,ssh-rsa
    PasswordAuthentication no
    ChallengeResponseAuthentication no
    MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com
    Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" > /etc/ssh/ssh_config

echo "
        #########################################################
        #                                                       #
        #      All connections are monitored and recorded.      #
        #     Disconnect IMMEDIATELY or risk your genitals!     #
        #                                                       #
        #########################################################" > /etc/issue.net

shred -vuzf /etc/ssh/ssh_host_*key*
ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -q -N "" < /dev/null
ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -q -N "" < /dev/null
/etc/init.d/ssh restart


# Config/harden PAM.
echo -e "\npassword   [success=1 default=ignore]      pam_unix.so nullok obscure minlen=8 sha512" >> /etc/pam.d/passwd

echo -e "\nsession    optional     pam_tmpdir.so
session    optional     pam_umask.so umask=077" >> /etc/pam.d/common-session

echo "auth     required       pam_securetty.so
auth     required       pam_unix_auth.so
auth     required       pam_warn.so
auth     required       pam_deny.so
auth     required       pam_tally.so onerr=fail no_magic_root
account  required       pam_unix_acct.so
account  required       pam_tally.so per_user deny=5 no_magic_root reset
account  required       pam_warn.so
account  required       pam_deny.so
password required       pam_unix_passwd.so
password required       pam_warn.so
password required       pam_deny.so
session  required       pam_unix_session.so
session  required       pam_warn.so
session  required       pam_deny.so" > /etc/pam.d/other

echo -e "\nsession  required   pam_limits.so" >> /etc/pam.d/login

cp /etc/security/limits.conf /etc/security/limits.conf.bak
echo "*              soft    core            0
*              hard    core            0
*              hard    rss             1000
*              hard    memlock         1000
*              hard    nproc           100
*              -       maxlogins       1
*              hard    data            5000000
*              hard    fsize           10000000
@adm           hard    core            10000000
@adm           hard    rss             10000000
@adm           soft    nproc           2000
@adm           hard    nproc           3000
@adm           hard    fsize           10000000
@adm           -       maxlogins       10" > /etc/security/limits.conf


# Config/harden login.
cp /etc/login.defs /etc/login.defs.bak
echo "MAIL_DIR        /var/mail
LOG_OK_LOGINS        no
FTMP_FILE       /var/log/btmp
SU_NAME         su
ENV_SUPATH      PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ENV_PATH        PATH=/usr/local/bin:/usr/bin:/bin
TTYGROUP        tty
TTYPERM         0600
ERASECHAR       0177
KILLCHAR        025
UMASK           022
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
UID_MIN         1000
UID_MAX         60000
GID_MIN         1000
GID_MAX         60000
LOGIN_TIMEOUT         60
CHFN_RESTRICT         rwh
DEFAULT_HOME     yes
USERGROUPS_ENAB    yes
FAILLOG_ENAB        yes
LOG_UNKFAIL_ENAB    no
SYSLOG_SU_ENAB      yes
SYSLOG_SG_ENAB      yes
ENCRYPT_METHOD  SHA512" > /etc/login.defs


# Config/harden GnuPG.
if [[ ! -e ~/.gnupg ]]; then
  gpg < /dev/null &>/dev/null &
  sleep 3
fi
cp ~/.gnupg/gpg.conf ~/.gnupg/gpg.conf.bak
echo "utf8-strings
no-permission-warning
no-greeting
no-emit-version
no-comments
keyid-format 0xlong
with-fingerprint
list-options show-uid-validity
verify-options show-uid-validity
no-use-agent
fixed-list-mode
sig-notation issuer-fpr@notations.openpgp.fifthhorseman.net=%g
keyserver hkp://hkps.pool.sks-keyservers.net no-cert-check
keyserver-options no-honor-keyserver-url
keyserver-options no-try-dns-srv
keyserver-options include-revoked
personal-cipher-preferences AES256 TWOFISH AES192 AES
personal-digest-preferences SHA512 SHA384 SHA256 SHA224
cert-digest-algo SHA512
default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
keyserver-options debug,verbose" > ~/.gnupg/gpg.conf


# Config Apt sources.
cp /etc/apt/sources.list /etc/apt/sources.list.bak
echo "deb http://deb.torproject.org/torproject.org jessie main
deb http://deb.torproject.org/torproject.org tor-experimental-0.2.7.x-jessie main
deb http://http.debian.net/debian/ jessie main contrib non-free
deb http://http.debian.net/debian/ jessie-updates main non-free contrib
deb http://security.debian.org/ jessie/updates main contrib non-free" > /etc/apt/sources.list

gpg --recv-keys A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
gpg --export 886DDD89 | apt-key add -


# Config debconf.
echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections


# Update, upgrade, and install.
apt-get update
apt-get upgrade -y
apt-get install -y deb.torproject.org-keyring
apt-get install -y apparmor apparmor-profiles apparmor-utils apt-listchanges apt-transport-tor attr cryptsetup curl debconf-utils fail2ban git gnupg-curl haveged iptables iptables-persistent logrotate lvm2 monit nethogs openvpn proxychains pwgen resolvconf screen secure-delete sudo tlsdate tor tor-arm tor-geoipdb torsocks unattended-upgrades


# Config/harden sysctl.conf.
cp /etc/sysctl.conf /etc/sysctl.conf.bak
echo "kernel.sysrq = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0" > /etc/sysctl.conf
sysctl -p


# Iptable rules.
echo "*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:fail2ban-ssh -

-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp --dport "$sshport" -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -m limit --limit 2/s -j ACCEPT
-A INPUT -p icmp --icmp-type echo-request -j DROP
-A INPUT -p icmp -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -m state --state INVALID -j DROP
-A fail2ban-ssh -j RETURN

COMMIT" > /etc/iptables/rules.v4

echo "*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]

-A INPUT -i lo -j DROP
-A INPUT -p tcp -j DROP
-A INPUT -p ipv6-icmp --icmpv6-type echo-request -j DROP
-A INPUT -p ipv6-icmp -j DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j DROP
-A INPUT -m state --state INVALID -j DROP

COMMIT" > /etc/iptables/rules.v6
chmod 600 /etc/iptables/rules.v4
chmod 600 /etc/iptables/rules.v6
iptables-restore < /etc/iptables/rules.v4
ip6tables-restore < /etc/iptables/rules.v6


# Config Unattended Upgrades.
echo 'APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
service unattended-upgrades restart


# Config Apparmor
sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 apparmor=1 security=apparmor"/' /etc/default/grub
update-grub


# Config Tor.
cp /etc/tor/torrc /etc/tor/torrc.bak
echo "
RunAsDaemon 1
CookieAuthentication 1
DisableDebuggerAttachment 0
StrictNodes 1
CloseHSServiceRendCircuitsImmediatelyOnTimeout 1
CloseHSClientCircuitsImmediatelyOnTimeout 1
FastFirstHopPK 0
AutomapHostsSuffixes .

## CONTROL PORT ##
ControlPort 9051

## DNS PORT ##
DNSPort 53 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort

## MONIT PORT ##
SocksPort 9050 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort

## PROXYCHAINS PORT ##
SocksPort 9060 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort

## HIDDEN SERVICE PORT ##
SocksPort 9061 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
HiddenServiceDir /var/lib/tor/ssh/ ## SSH SERVICE DIR ##
HiddenServicePort "$sshport" 127.0.0.1:"$sshport" ## SSH SERVICE PORT ##

## GNUPG PORT ##
SocksPort 9062 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort

## CURL PORT ##
SocksPort 9063 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort


SocksPort 9064 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 9065 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 9066 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 9067 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 9068 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 9069 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
SocksPort 9070 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort" > /etc/tor/torrc
/etc/init.d/tor reload


# Config Apt for Tor.
sed -i '/debian\.net/d' /etc/apt/sources.list
sed -i 's|http\:|tor\:|g' /etc/apt/sources.list
echo "deb tor://vwakviie2ienjx6t.onion/debian/ jessie main non-free contrib
deb tor://vwakviie2ienjx6t.onion/debian/ jessie-updates main non-free contrib" >> /etc/apt/sources.list


# Config misc. for Tor.
sed -i 's|9050|9060|' /etc/proxychains.conf
echo "keyserver-options http-proxy=socks5-hostname://127.0.0.1:9062" >> ~/.gnupg/gpg.conf


# Config network/DNS.
cp /etc/network/interfaces /etc/network/interfaces.bak
echo "source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

allow-hotplug eth0
iface eth0 inet dhcp
dns-nameserver 127.0.0.1" > /etc/network/interfaces
/etc/init.d/networking restart


# Config screen.
cp /etc/screenrc /etc/screenrc.bak
echo "deflogin on
bind ^k
bind ^\
bind \\ quit
bind K kill
bind I login on
bind O login off
bind } history
termcapinfo vt100 dl=5\E[M
termcapinfo xterm*|rxvt*|kterm*|Eterm* hs:ts=\E]0;:fs=\007:ds=\E]0;\007
termcapinfo xterm*|linux*|rxvt*|Eterm* OP
termcapinfo xterm 'is=\E[r\E[m\E[2J\E[H\E[?7h\E[?1;4;6l'
defnonblock 5
startup_message off
defscrollback 10000
altscreen on
defflow auto
shell -bash
defutf8 on
vbell off
shelltitle '$ |bash'
terminfo rxvt-unicode 'Co#256:AB=\E[48;5;%dm:AF=\E[38;5;%dm'
hardstatus on
hardstatus alwayslastline
hardstatus string '%{= G}[%{g}host:%{G}%h]%{g}[%= %{= w}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{r}load:%{R}%l%{g}][%{c}%m-%d~%{C}%c:%s%{g}]'
activity '%c activity -> %n%f %t'" > /etc/screenrc


# Config/harden /etc/bash.bashrc.
cp /etc/bash.bashrc /etc/bash.bashrc.bak
echo '[ -z "$PS1" ] && return
shopt -s checkwinsize
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi
PS1='"'${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '"'
if [ -x /usr/lib/command-not-found -o -x /usr/share/command-not-found/command-not-found ]; then
        function command_not_found_handle {
                if [ -x /usr/lib/command-not-found ]; then
                   /usr/lib/command-not-found -- "$1"
                   return $?
                elif [ -x /usr/share/command-not-found/command-not-found ]; then
                   /usr/share/command-not-found/command-not-found -- "$1"
                   return $?
                else
                   printf "%s: command not found\n" "$1" >&2
                   return 127
                fi
        }
fi
HISTSIZE=1000
HISTFILESIZE=1000
HISTFILE="~/.bash_history"

alias tor-curl="curl -x socks5://127.0.0.1:9063"
alias tor-wget="torify wget"
alias tor-git="torify git"' > /etc/bash.bashrc
cp /etc/bash.bashrc ~/.bashrc


# Config/harden .profile.
cp ~/.profile ~/.profile.bak
cp /etc/bash.bashrc ~/.profile
echo "export HISTSIZE HISTFILESIZE HISTFILE" >> ~/.profile


# Config Monit.
cp /etc/monit/monitrc /etc/monit/monitrc.bak
echo 'set daemon 120
set logfile /var/log/monit.log
set idfile /var/lib/monit/id
set statefile /var/lib/monit/state
set eventqueue
    basedir /var/lib/monit/events
    slots 100
include /etc/monit/conf.d/*

check process tor with pidfile /var/run/tor/tor.pid
group tor
start program = "/etc/init.d/tor start"
stop program = "/etc/init.d/tor stop"
if failed port 9050 type tcp
   with timeout 5 seconds
   then restart
if 3 restarts within 5 cycles then timeout

check process fail2ban with pidfile /var/run/fail2ban/fail2ban.pid
start program = "/etc/init.d/fail2ban start"
stop program = "/etc/init.d/fail2ban stop"

check process tlsdated with pidfile /var/run/tlsdated.pid
start program = "/etc/init.d/tlsdated start"
stop program = "/etc/init.d/tlsdated stop"

check process sshd with pidfile /var/run/sshd.pid
start program = "/etc/init.d/ssh start"
stop program = "/etc/init.d/ssh stop"
if failed port '"$sshport"' type tcp
   with timeout 5 seconds
   then restart
if 3 restarts within 5 cycles then timeout' > /etc/monit/monitrc


# Config Logrotate.
cp /etc/logrotate.conf /etc/logrotate.conf.bak
echo "daily
rotate 2
create
compress
include /etc/logrotate.d
/var/log/wtmp {
    rotate 2
    daily
    compress
    missingok
    notifempty
    create 0664 root utmp
}
/var/log/btmp {
    rotate 2
    daily
    compress
    missingok
    notifempty
    create 0664 root utmp
}" > /etc/logrotate.conf

echo "/var/log/alternatives.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root root
}" > /etc/logrotate.d/alternatives.log

echo "/var/log/apt/history.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root root
}
/var/log/apt/term.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/apt

echo "/var/log/auth.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/auth

echo "/var/log/daemon.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/daemon

echo "/var/log/dpkg.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root root
}" > /etc/logrotate.d/dpkg

echo "/var/log/fail2ban.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/fail2ban

echo "/var/log/kern.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/kern.log

echo "/var/log/mail.err {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}
/var/log/mail.info {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}
/var/log/mail.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}
/var/log/mail.warn {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/mail

echo "/var/log/messages {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/messages

echo "/var/log/monit.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/monit

echo "/var/log/syslog {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/syslog

echo "/var/log/tor/log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 debian-tor adm
}
/var/log/tor/notices.log {
   rotate 2
   daily
   compress
   missingok
   notifempty
   create 660 debian-tor adm
}" > /etc/logrotate.d/tor

echo "/var/log/unattended-upgrades/unattended-upgrades-shutdown.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root root
}

/var/log/unattended-upgrades/unattended-upgrades.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root root
}" > /etc/logrotate.d/unattended-upgrades

echo "/var/log/user.log {
        rotate 2
        daily
        compress
        missingok
        notifempty
        create 660 root adm
}" > /etc/logrotate.d/user

chmod 644 /etc/logrotate.d/*
chown root:root /etc/logrotate.d/*


# Lock files, clean up.
srm -dr ~/.bash_history /var/log/wtmp /var/log/lastlog /var/run/utmp /var/log/mail.* /var/log/syslog* /var/log/messages* /var/log/auth.log* /var/log/apt/* &>/dev/null &
chattr +i /etc/ssh/sshd_config /etc/ssh/ssh_config /etc/ssh/ssh_host_* ~/.gnupg/gpg.conf ~/.ssh/authorized_keys /etc/network/interfaces


# Finish.
clear
echo "
[+]  SSH Port:  "$sshport"
[+]  Authorized SSH Key: $(ssh-keygen -lf ~/.ssh/authorized_keys | cut -b 6- | cut -b -48)
[+]  SSH Hidden Service:  http://$(cat /var/lib/tor/ssh/hostname):"$sshport"
[+]  RSA Host Key:  $(ssh-keygen -lf /etc/ssh/ssh_host_rsa_key | cut -b 6- | cut -b -48)
[+]  ED25519 Host Key:  $(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key | cut -b 5- | cut -b -48)

"
read -p "Press enter to exit. "
exit 0
