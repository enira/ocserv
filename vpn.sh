#!/bin/bash

# Check if user is root or sudo
if ! [ $(id -u) = 0 ]; then echo "Please run this script as sudo or root"; exit 1 ; fi

# Colors to use for output
YELLOW='\033[1;33m'
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging of installation
LOG="/tmp/ocserv.log"

# Parameters
while [ "$1" != "" ]; do
    case $1 in
        -d | --dns )
            shift
            dnsname="$1"
            ;;
        -u | --username )
            shift
            vpnusername="$1"
            ;;
        -p | --password )
            shift
            vpnpassword="$1"
            ;;
        -e | --email )
            shift
            email="$1"
            ;;
    esac
    shift
done

# Get current primary network interface
interface=`route | grep '^default' | grep -o '[^ ]*$'`

echo -e "${CYAN}Found primary interface: $interface...${NC}"

# Ask for info if not given
if [[ -z $dnsname ]]; then
    read -p "Enter VPN DNS name: " dnsname
    
fi

if [[ -z $vpnusername ]]; then
    read -p "Enter VPN Username: " vpnusername
    
fi

if [[ -z $vpnpassword ]]; then
    read -p "Enter VPN Password: " vpnpassword
    
fi

if [[ -z $email ]]; then
    read -p "Enter SSL Certificate Registration Email: " email
    
fi

# Update apt
apt-get update

# Install packages
echo -e "${CYAN}Installing packages. This might take a few minutes...${NC}"

apt-get -y install ocserv ufw &>> ${LOG}

if [ $? -ne 0 ]; then
    echo -e "${RED}Failed. See ${LOG}${NC}"
    exit 1
else
    echo -e "${GREEN}OK${NC}"
fi

# Opening up the firewall port
echo -e "${CYAN}Enabling firewall...${NC}"

ufw allow 22
ufw allow 80
ufw allow 443

echo "y" | sudo ufw enable

# Getting a certificate from Lets Encrypt
echo -e "${CYAN}Requesting a certificate for $dns registered to $email...${NC}"

add-apt-repository ppa:certbot/certbot -y	
apt-get update
apt-get -y install certbot &>> ${LOG}

certbot certonly --standalone --agree-tos --no-eff-email -m $email --preferred-challenges http -d $dnsname

echo -e "${CYAN}Stopping services...${NC}"

systemctl stop ocserv.socket
systemctl disable ocserv.socket


echo -e "${CYAN}Creating IP forwarding rules...${NC}"
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

echo -e "${CYAN}Writing configuration files...${NC}"

# Remove all previous config files
rm /etc/default/ufw
rm /etc/ufw/before.rules
rm /etc/ocserv/ocserv.conf

# Create username / password
echo "$vpnpassword" | ocpasswd -c /etc/ocserv/ocpasswd $vpnusername
chmod 700 /etc/ocserv/ocpasswd

# Write all files
cat >> /etc/default/ufw <<EOL
# /etc/default/ufw

IPV6=yes
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="ACCEPT"
DEFAULT_APPLICATION_POLICY="SKIP"
MANAGE_BUILTINS=no
IPT_SYSCTL=/etc/ufw/sysctl.conf
IPT_MODULES="nf_conntrack_ftp nf_nat_ftp nf_conntrack_netbios_ns"
EOL

cat >> /etc/systemd/system/ocserv.service <<EOL
[Unit]
Description=OpenConnect SSL VPN server
Documentation=man:ocserv(8)
After=network-online.target

[Service]
PrivateTmp=true
PIDFile=/var/run/ocserv.pid
ExecStart=/usr/sbin/ocserv --foreground --pid-file /var/run/ocserv.pid --config /etc/ocserv/ocserv.conf
ExecReload=/bin/kill -HUP $MAINPID

[Install]
WantedBy=multi-user.target
EOL

cat >> /etc/ocserv/ocserv.conf <<EOL
auth = "plain[passwd=/etc/ocserv/ocpasswd]"
tcp-port = 443
udp-port = 443
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
default-domain = DNSNAME
server-cert = /etc/letsencrypt/live/DNSNAME/fullchain.pem
server-key = /etc/letsencrypt/live/DNSNAME/privkey.pem
ca-cert = /etc/ssl/certs/ssl-cert-snakeoil.pem
isolate-workers = true
max-clients = 16
max-same-clients = 4
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 3
max-ban-score = 50
ban-reset-time = 300
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-utmp = true
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
ipv4-network = 192.168.10.0
ipv4-netmask = 255.255.255.0
tunnel-all-dns = true
dns = 8.8.8.8
ping-leases = false
route = default
no-route = 192.168.10.0/255.255.255.0
cisco-client-compat = true
dtls-legacy = true
EOL

cat >> /etc/ocserv/ocserv.conf <<EOL
# /etc/default/ufw

IPV6=yes
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="ACCEPT"
DEFAULT_APPLICATION_POLICY="SKIP"
MANAGE_BUILTINS=no
IPT_SYSCTL=/etc/ufw/sysctl.conf
IPT_MODULES="nf_conntrack_ftp nf_nat_ftp nf_conntrack_netbios_ns"
EOL

cat >> /etc/ufw/before.rules <<EOL
#
# rules.before
#

*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o eth0 -j MASQUERADE

COMMIT

*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]

-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-input -m conntrack --ctstate INVALID -j ufw-logging-deny
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT
-A ufw-before-input -j ufw-not-local
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN
-A ufw-not-local -m addrtype --dst-type MULTICAST -j RETURN
-A ufw-not-local -m addrtype --dst-type BROADCAST -j RETURN
-A ufw-not-local -m limit --limit 3/min --limit-burst 10 -j ufw-logging-deny
-A ufw-not-local -j DROP
-A ufw-before-input -p udp -d 224.0.0.251 --dport 5353 -j ACCEPT
-A ufw-before-input -p udp -d 239.255.255.250 --dport 1900 -j ACCEPT

COMMIT
EOL

# Change interface & dns name
sed -i -e "s/\eth0/$interface/" /etc/ufw/before.rules 
sed -i -e "s/\DNSNAME/$dnsname/" /etc/ocserv/ocserv.conf

chmod 640 /etc/ufw/before.rules
chmod 644 /etc/default/ufw

systemctl enable ocserv

reboot
