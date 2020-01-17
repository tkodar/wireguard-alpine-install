#!/bin/bash
# 
# alpine-wireguard-install.sh
#
# 20200112
#
# Script to set up WireGuard on Alpine linux
# 
# This script creates a WireGuard NIC
# and creates a configuration for WireGuard
#
# This script does NOT handle IPv6. Only IPv4!
#
# This script was originally based on angristan wireguard-install.sh
# https://github.com/angristan/wireguard-install
#

if [ "$EUID" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

echo "This script will install and configure WireGuard on Alpine Linux."

if [[ ! -e /etc/alpine-release ]]; then
    echo -e "\nThis does not look like a Alpine enviroment."
    echo "I will exit this..."
    exit 1
fi

# Install WireGuard tools and module
echo "Installing WireGuard.."
apk add wireguard-tools wireguard-tools-wg

echo -e "\nPlease change default value accordingly!\n"

# Detect public interface and pre-fill for the user
while true; do
    SERVER_PUB_NIC="$(ip -4 route ls | grep default | awk '{print $5}')"
    read -rp "Public interface: " -e -i "$SERVER_PUB_NIC" SERVER_PUB_NIC
    if ip -4 a show $SERVER_PUB_NIC > /dev/null; then
        break
    else
        echo -e "\nPlease enter a network interface that exist"
        echo -e "If you don't know, please use default\n"
    fi
done

# Detect public IPv4 address and pre-fill for the user
SERVER_PUB_IPV4=$(wget -qO- ifconfig.me 2>/dev/null) || SERVER_PUB_IPV4=$(ip -4 a show $SERVER_PUB_NIC | grep 'inet' | cut -d'/' -f1 | awk '{print $2}')
echo -e "\nPleaser enter IP or FQDN that client can use to reach VPN server."
read -rp "" -e -i "$SERVER_PUB_IPV4" SERVER_PUB_IP

# WireGuard NIC
SERVER_WG_NIC="wg0"
read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC

# WireGuard network mask
SERVER_WG_IPV4_MASK="30"
echo -e "\nPlease enter a network mask to be used for WireGuard"
echo -e "Default value '30' only allows 1 client (server uses 1 IP) to be connected at any time."
echo -e "'29' allows 5 simultaneously clients"
echo -e "'24' allows 253 simultaneously clients"
echo -e "Please consult http://jodies.de/ipcalc\n"
echo -e "Expects value between 24 and 30."
# Check user input
while true; do
    read -rp "Server's WireGuard IPv4 network mask: " -e -i "$SERVER_WG_IPV4_MASK" SERVER_WG_IPV4_MASK
    if [[ $SERVER_WG_IPV4_MASK ]] && (( $SERVER_WG_IPV4_MASK >= 24 && $SERVER_WG_IPV4_MASK <= 30 )); then
        break
    else
        echo -e "\nThis script only supports netmask between 24 and 30!\n"
        SERVER_WG_IPV4_MASK="30"
    fi
done

# Function to test a IP octet
testOCT () {
    # It is known that a valid octed is between 0 and 255
    if (( $1 >= 0 && $1 <= 255 )); then
        return 0
    else
        return 1
    fi
}

# Function test if a IP is valid
# My brain cannot handle complex regex...
testIP() {
    # Test for number of dots '.'
    if (( $(echo $1 | sed 's/\./\n/g' | wc -l) == 4 )); then
        # Break up IP into octets
        for i in $(echo $1 | sed 's/\./ /g'); do
            # Test octet
            if ! $(testOCT $i); then
                return 1
            fi
        done
    else
        return 1
    fi
    return 0
}

printIPError() {
    echo -e "\nPlease enter a private (RFC 1918) network"
    echo -e "\t10.0.0.0\t- 10.255.255.255  (10/8 prefix)"
    echo -e "\t172.16.0.0\t- 172.31.255.255  (172.16/12 prefix)"
    echo -e "\t192.168.0.0\t- 192.168.255.255 (192.168/16 prefix)\n"
}

# WireGuard network
while true; do
    SERVER_WG_IPV4="172.19.66.1"
    read -rp "Server's WireGuard IPv4 network " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4
    if testIP $SERVER_WG_IPV4 ; then
        # This if tests for RFC 1918 networks
        if $(echo $SERVER_WG_IPV4 | grep -E '^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.|^10\.|^192.168\.' &> /dev/null); then
            # This break is the only way to end endless loop
            break 
        else
            printIPError
        fi
    else
        echo -e "\nNot a valid IP!"
        printIPError
    fi
done

# Creating client IP
CLIENT_IP=$(echo $SERVER_WG_IPV4 | cut -d'.' -f-3).$(($(echo $SERVER_WG_IPV4 | cut -d'.' -f4)+1))/$SERVER_WG_IPV4_MASK

# WireGuard server port
SERVER_PORT=1194
echo -e "\nPleaser enter a public port that client can use to reach VPN server."
read -rp "Server's WireGuard port " -e -i "$SERVER_PORT" SERVER_PORT

# WireGuard clients
CLIENT_WG_IPV4="0.0.0.0/0"
echo -e "\nPlease enter clients IP address in the format <IP>/<Network mask>."
echo -e "Default 0.0.0.0/0 allows all IPs to connect.\n"
read -rp "Client's WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4" CLIENT_WG_IPV4

# Ask for pre-shared symmetric key
IS_PRE_SYMM="y"
echo -e "\nUsing a preshared key enhances security."
read -rp "Do you want to use pre-shared symmetric key? [Y/n]: " -e -i "$IS_PRE_SYMM" IS_PRE_SYMM

# Client endpoint
ENDPOINT="$SERVER_PUB_IP:$SERVER_PORT"

# Get DNS server(s)
CLIENT_DNS=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/, /g')

# Generate key pair for the server
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# Generate key pair for the server
CLIENT_PRIV_KEY=$(wg genkey)
CLIENT_PUB_KEY=$(echo "$CLIENT_PRIV_KEY" | wg pubkey)

# Add WireGuard NIC to interfaces
cat <<EOF > /etc/wireguard/$SERVER_WG_NIC.conf
[Interface]
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY

[Peer]
PublicKey = $CLIENT_PUB_KEY
AllowedIPs = $CLIENT_WG_IPV4
EOF

# Create client file
cat <<EOF > $HOME/$SERVER_WG_NIC-client.conf
[Interface]
PrivateKey = $CLIENT_PRIV_KEY
Address = $CLIENT_IP
DNS = $CLIENT_DNS

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0
EOF

# Add pre shared symmetric key to respective files
case "$IS_PRE_SYMM" in
    [yY][eE][sS]|[yY])
        CLIENT_SYMM_PRE_KEY=$( wg genpsk )
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$HOME/$SERVER_WG_NIC-client.conf"
        ;;
esac

chmod 600 -R /etc/wireguard/

IPV4_NETMASK="255.255.255.252"
case $SERVER_WG_IPV4_MASK in
    "30")
        IPV4_NETMASK="255.255.255.252"
        ;;
    "29")
        IPV4_NETMASK="255.255.255.248"
        ;;
    "28")
        IPV4_NETMASK="255.255.255.240"
        ;;
    "27")
        IPV4_NETMASK="255.255.255.224"
        ;;
    "26")
        IPV4_NETMASK="255.255.255.192"
        ;;
    "25")
        IPV4_NETMASK="255.255.255.128"
        ;;
    "24")
        IPV4_NETMASK="255.255.255.0"
        ;;
    *)
        # This should never happen...
        echo "Error - netmask not supported by this script"
        echo "exiting.. "
        exit 1
        ;;
esac

# Enable routing on the server
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/wg.conf
echo "1" > /proc/sys/net/ipv4/ip_forward

# Add wireguard NIC to /etc/network/interfaces
cat <<EOF >> /etc/network/interfaces

auto $SERVER_WG_NIC
iface $SERVER_WG_NIC inet static
    address $SERVER_WG_IPV4
    netmask $IPV4_NETMASK
    pre-up ip link add dev $SERVER_WG_NIC type wireguard
    pre-up wg setconf $SERVER_WG_NIC /etc/wireguard/$SERVER_WG_NIC.conf
    post-up iptables -A FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
    post-down ip link delete dev $SERVER_WG_NIC
    post-down iptables -D FORWARD -i $SERVER_WG_NIC -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
EOF

echo -e "\n\nStarting WireGuard VPN on $SERVER_WG_NIC"
ifup $SERVER_WG_NIC

echo -e "\nYou control VPN by using 'ifup' and 'ifdown'"
echo -e "\tifup $SERVER_WG_NIC"
echo -e "\tifdown $SERVER_WG_NIC"

echo -e "\n\n Copy below client configuration to client"
echo "#-------------------------------------------------------------------"
cat $HOME/$SERVER_WG_NIC-client.conf
echo "#-------------------------------------------------------------------"