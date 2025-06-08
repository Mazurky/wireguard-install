#!/bin/bash
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check for whiptail
USE_WHIPTAIL=true
if ! command -v whiptail &>/dev/null; then
	echo -e "${YELLOW}Whiptail not found, falling back to standard prompts.${NC}"
	USE_WHIPTAIL=false
fi

function prompt_message() {
	local message="$1" color="${NC}"
	case "$2" in
	error) color="${RED}" ;;
	warning) color="${YELLOW}" ;;
	success) color="${GREEN}" ;;
	info) color="${BLUE}" ;;
	esac
	if $USE_WHIPTAIL; then
		whiptail --msgbox "$message" 15 80 --title "WireGuard Installer"
	fi
	printf "%b\n" "${color}${message}${NC}"
}

function prompt_input() {
	local raw_prompt="$1" default="$2" INPUT EXITSTATUS prompt
	prompt=$(printf "%b" "$raw_prompt")
	if $USE_WHIPTAIL; then
		INPUT=$(whiptail --inputbox "$prompt" 15 80 "$default" --title "WireGuard Installer" 3>&1 1>&2 2>&3)
		EXITSTATUS=$?
		if [ $EXITSTATUS -ne 0 ]; then
			echo ""
			return 1
		fi
	else
		read -rp "$prompt " -e -i "$default" INPUT || return 1
	fi
	echo "$INPUT"
	return 0
}

CONTINUE=""

function prompt_yes_no() {
	local raw_prompt="$1" default="$2" INPUT prompt
	prompt=$(printf "%b" "$raw_prompt")
	if $USE_WHIPTAIL; then
		if [[ "$default" == "y" ]]; then
			whiptail --yesno "$prompt" 15 80 --title "WireGuard Installer"
		else
			whiptail --yesno "$prompt" 15 80 --defaultno --title "WireGuard Installer"
		fi

		if [[ $? -eq 0 ]]; then
			CONTINUE="y"
		else
			CONTINUE="n"
		fi
	else
		read -rp "$prompt [y/n]: " -e -i "$default" INPUT
		CONTINUE="${INPUT,,}"
	fi
}

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		prompt_message "You need to run this script as root." error
		exit 1
	fi
}

function checkVirt() {
	function openvzErr() {
		prompt_message "OpenVZ is not supported." error
		exit 1
	}
	function lxcErr() {
		message="LXC is not supported (yet).\n\
WireGuard can technically run in an LXC container,\n\
but the kernel module has to be installed on the host,\n\
the container has to be run with some specific parameters\n\
and only the tools need to be installed in the container."
		prompt_message "$message" error
		exit 1
	}
	if command -v virt-what &>/dev/null; then
		if [ "$(virt-what)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(virt-what)" == "lxc" ]; then
			lxcErr
		fi
	else
		if [ "$(systemd-detect-virt)" == "openvz" ]; then
			openvzErr
		fi
		if [ "$(systemd-detect-virt)" == "lxc" ]; then
			lxcErr
		fi
	fi
}

function checkOS() {
	if [ -r /etc/os-release ]; then
		source /etc/os-release
	else
		echo "/etc/os-release not found." >&2
		exit 1
	fi
	OS="${ID}"
	if [[ ${OS} == "debian" || ${OS} == "raspbian" ]]; then
		if [[ ${VERSION_ID} -lt 10 ]]; then
			prompt_message "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster or later" error
			exit 1
		fi
		OS=debian # overwrite if raspbian
	elif [[ ${OS} == "ubuntu" ]]; then
		RELEASE_YEAR=$(echo "${VERSION_ID}" | cut -d'.' -f1)
		if [[ ${RELEASE_YEAR} -lt 18 ]]; then
			prompt_message "Your version of Ubuntu (${VERSION_ID}) is not supported. Please use Ubuntu 18.04 or later" error
			exit 1
		fi
	elif [[ ${OS} == "fedora" ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			prompt_message "Your version of Fedora (${VERSION_ID}) is not supported. Please use Fedora 32 or later" error
			exit 1
		fi
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 7* ]]; then
			prompt_message "Your version of CentOS (${VERSION_ID}) is not supported. Please use CentOS 8 or later" error
			exit 1
		fi
	elif [[ -e /etc/oracle-release ]]; then
		source /etc/os-release
		OS=oracle
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	elif [[ -e /etc/alpine-release ]]; then
		OS=alpine
		if ! command -v virt-what &>/dev/null; then
			apk update && apk add virt-what
		fi
	else
		prompt_message "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, AlmaLinux, Oracle or Arch Linux system" error
		exit 1
	fi
}

function getHomeDirForClient() {
	local CLIENT_NAME=$1

	if [ -z "${CLIENT_NAME}" ]; then
		prompt_message "Error: getHomeDirForClient() requires a client name as argument" error
		exit 1
	fi

	# Home directory of the user, where the client configuration will be written
	if [ -e "/home/${CLIENT_NAME}" ]; then
		# if $1 is a user name
		HOME_DIR="/home/${CLIENT_NAME}"
	elif [ "${SUDO_USER}" ]; then
		# if not, use SUDO_USER
		if [ "${SUDO_USER}" == "root" ]; then
			# If running sudo as root
			HOME_DIR="/root"
		else
			HOME_DIR="/home/${SUDO_USER}"
		fi
	else
		# if not SUDO_USER, use /root
		HOME_DIR="/root"
	fi

	echo "$HOME_DIR"
}

function initialCheck() {
	isRoot
	checkOS
	checkVirt
}

function installQuestions() {
	message="Welcome to the WireGuard installer\n\n\
This is a fork of the angristan/wireguard-install script that adds a CLI-based graphical interface using Whiptail for an improved user experience. If Whiptail is not available on the system, the script gracefully falls back to the original standard prompts."
	prompt_message "$message" info

	prompt_yes_no "Do you want to continue?" "y"
	if [[ "$CONTINUE" != "y" ]]; then
		prompt_message "Installation aborted!" info
		exit 0
	fi

	# Detect public IPv4 or IPv6 address and pre-fill for the user
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		# Detect public IPv6 address
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	SERVER_PUB_IP=$(prompt_input "IPv4 or IPv6 public address:" "$SERVER_PUB_IP") || {
		prompt_message "Installation aborted!" info
		exit 0
	}

	# Detect public interface and pre-fill for the user
	SERVER_NIC="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1)}' | head -1)"
	until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
		SERVER_PUB_NIC=$(prompt_input "Public interface:" "$SERVER_NIC") || {
			prompt_message "Installation aborted!" info
			exit 0
		}

	done

	until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
		SERVER_WG_NIC=$(prompt_input "WireGuard interface name:" "wg0") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
	done

	until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
		SERVER_WG_IPV4=$(prompt_input "Server WireGuard IPv4:" "10.66.66.1") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
	done

	until [[ ${SERVER_WG_IPV6} =~ ^([a-f0-9]{1,4}:){3,4}: ]]; do
		SERVER_WG_IPV6=$(prompt_input "Server WireGuard IPv6:" "fd42:42:42::1") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
	done

	# Generate random number within private ports range
	until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
		SERVER_PORT=$(prompt_input "Server WireGuard port [1-65535]:" "$(shuf -i49152-65535 -n1)") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
	done

	# Adguard DNS by default
	until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		CLIENT_DNS_1=$(prompt_input "First DNS resolver for clients:" "1.1.1.1") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
	done
	until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
		CLIENT_DNS_2=$(prompt_input "Second DNS resolver (optional):" "1.0.0.1") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
		if [[ ${CLIENT_DNS_2} == "" ]]; then
			CLIENT_DNS_2="${CLIENT_DNS_1}"
		fi
	done

	until [[ ${ALLOWED_IPS} =~ ^.+$ ]]; do
		message="WireGuard uses a parameter called AllowedIPs to determine what is routed over the VPN.\n\nAllowed IPs list for generated clients (default route everything):"
		ALLOWED_IPS=$(prompt_input "$message" "0.0.0.0/0,::/0") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
		if [[ ${ALLOWED_IPS} == "" ]]; then
			ALLOWED_IPS="0.0.0.0/0,::/0"
		fi
	done

	prompt_message "All set! Ready to install WireGuard." success
}

function installWireGuard() {
	# Run setup questions first
	installQuestions

	# Install WireGuard tools and module
	if [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'debian' && ${VERSION_ID} -gt 10 ]]; then
		apt-get update
		apt-get install -y wireguard iptables resolvconf qrencode
	elif [[ ${OS} == 'debian' ]]; then
		if ! grep -rqs "^deb .* buster-backports" /etc/apt/; then
			echo "deb http://deb.debian.org/debian buster-backports main" >/etc/apt/sources.list.d/backports.list
			apt-get update
		fi
		apt update
		apt-get install -y iptables resolvconf qrencode
		apt-get install -y -t buster-backports wireguard
	elif [[ ${OS} == 'fedora' ]]; then
		if [[ ${VERSION_ID} -lt 32 ]]; then
			dnf install -y dnf-plugins-core
			dnf copr enable -y jdoss/wireguard
			dnf install -y wireguard-dkms
		fi
		dnf install -y wireguard-tools iptables qrencode
	elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
		if [[ ${VERSION_ID} == 8* ]]; then
			yum install -y epel-release elrepo-release
			yum install -y kmod-wireguard
			yum install -y qrencode # not available on release 9
		fi
		yum install -y wireguard-tools iptables
	elif [[ ${OS} == 'oracle' ]]; then
		dnf install -y oraclelinux-developer-release-el8
		dnf config-manager --disable -y ol8_developer
		dnf config-manager --enable -y ol8_developer_UEKR6
		dnf config-manager --save -y --setopt=ol8_developer_UEKR6.includepkgs='wireguard-tools*'
		dnf install -y wireguard-tools qrencode iptables
	elif [[ ${OS} == 'arch' ]]; then
		pacman -S --needed --noconfirm wireguard-tools qrencode
	elif [[ ${OS} == 'alpine' ]]; then
		apk update
		apk add wireguard-tools iptables libqrencode-tools
	fi

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}" >/etc/wireguard/params

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	if [[ ${OS} == 'alpine' ]]; then
		sysctl -p /etc/sysctl.d/wg.conf
		rc-update add sysctl
		ln -s /etc/init.d/wg-quick "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
		rc-service "wg-quick.${SERVER_WG_NIC}" start
		rc-update add "wg-quick.${SERVER_WG_NIC}"
	else
		sysctl --system

		systemctl start "wg-quick@${SERVER_WG_NIC}"
		systemctl enable "wg-quick@${SERVER_WG_NIC}"
	fi

	newClient
	prompt_message "If you want to add more clients, you simply need to run this script another time!" success

	# Check if WireGuard is running
	if [[ ${OS} == 'alpine' ]]; then
		rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status
	else
		systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	fi
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		prompt_message "WireGuard does not seem to be running." warning
		if [[ ${OS} == 'alpine' ]]; then
			prompt_message "You can check if WireGuard is running with: rc-service wg-quick.${SERVER_WG_NIC} status" warning
		else
			prompt_message "You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}" warning
		fi
		prompt_message "If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!" warning
	else # WireGuard is running
		prompt_message "WireGuard is running." success
		if [[ ${OS} == 'alpine' ]]; then
			prompt_message "You can check the status of WireGuard with: rc-service wg-quick.${SERVER_WG_NIC} status" info
		else
			prompt_message "You can check the status of WireGuard with: systemctl status wg-quick@${SERVER_WG_NIC}" info
		fi
		prompt_message "If you don't have internet connectivity from your client, try to reboot the server." warning
	fi
}

function newClient() {
	# If SERVER_PUB_IP is IPv6, add brackets if missing
	if [[ ${SERVER_PUB_IP} =~ .*:.* ]]; then
		if [[ ${SERVER_PUB_IP} != *"["* ]] || [[ ${SERVER_PUB_IP} != *"]"* ]]; then
			SERVER_PUB_IP="[${SERVER_PUB_IP}]"
		fi
	fi
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	until [[ ${CLIENT_NAME} =~ ^[a-zA-Z0-9_-]+$ && ${CLIENT_EXISTS} == '0' && ${#CLIENT_NAME} -lt 16 ]]; do
		CLIENT_NAME=$(prompt_input "Client configuration\n\
The client name must consist of alphanumeric character(s). It may also include underscores or dashes and can't exceed 15 chars.\n\n\
Client name:" "${CLIENT_NAME}") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
		CLIENT_EXISTS=$(grep -c -E "^### Client ${CLIENT_NAME}\$" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${CLIENT_EXISTS} != 0 ]]; then
			prompt_message "A client with the specified name was already created, please choose another name." warning
		fi
	done

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		prompt_message "The subnet configured supports only 253 clients." error
		exit 1
	fi

	BASE_IP=$(echo "$SERVER_WG_IPV4" | awk -F '.' '{ print $1"."$2"."$3 }')
	until [[ ${IPV4_EXISTS} == '0' ]]; do
		DOT_IP=$(prompt_input "Client WireGuard IPv4: ${BASE_IP}." "${DOT_IP}") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
		CLIENT_WG_IPV4="${BASE_IP}.${DOT_IP}"
		IPV4_EXISTS=$(grep -c "$CLIENT_WG_IPV4/32" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV4_EXISTS} != 0 ]]; then
			prompt_message "A client with the specified IPv4 was already created, please choose another IPv4." warning
		fi
	done

	BASE_IP=$(echo "$SERVER_WG_IPV6" | awk -F '::' '{ print $1 }')
	until [[ ${IPV6_EXISTS} == '0' ]]; do
		DOT_IP=$(prompt_input "Client WireGuard IPv6: ${BASE_IP}::" "${DOT_IP}") || {
			prompt_message "Installation aborted!" info
			exit 0
		}
		CLIENT_WG_IPV6="${BASE_IP}::${DOT_IP}"
		IPV6_EXISTS=$(grep -c "${CLIENT_WG_IPV6}/128" "/etc/wireguard/${SERVER_WG_NIC}.conf")

		if [[ ${IPV6_EXISTS} != 0 ]]; then
			prompt_message "A client with the specified IPv6 was already created, please choose another IPv6." warning
		fi
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = ${ALLOWED_IPS}" >"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")

	# Generate QR code if qrencode is installed
	if command -v qrencode &>/dev/null; then
		echo "Here is your client config file as a QR Code:"
		qrencode -t ansiutf8 -l L <"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf" # cant display this in whiptail
	fi

	prompt_message "Your client config file is in ${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf" success
}

function listClients() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} -eq 0 ]]; then
		prompt_message "You have no existing clients!" info
		exit 1
	fi

	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
}

function revokeClient() {
	NUMBER_OF_CLIENTS=$(grep -c -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf")
	if [[ ${NUMBER_OF_CLIENTS} == '0' ]]; then
		prompt_message "You have no existing clients!" info
		exit 1
	fi

	prompt_message "Select the existing client you want to revoke" info
	grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | nl -s ') '
	until [[ ${CLIENT_NUMBER} -ge 1 && ${CLIENT_NUMBER} -le ${NUMBER_OF_CLIENTS} ]]; do
		if [[ ${CLIENT_NUMBER} == '1' ]]; then
			#read -rp "Select one client [1]: " CLIENT_NUMBER
			CLIENT_NUMBER=$(prompt_input "Select one client [1]: " "1")
		else
			#read -rp "Select one client [1-${NUMBER_OF_CLIENTS}]: " CLIENT_NUMBER
			CLIENT_NUMBER=$(prompt_input "Select one client [1-${NUMBER_OF_CLIENTS}]: " "1")
		fi
	done

	# match the selected number to a client name
	CLIENT_NAME=$(grep -E "^### Client" "/etc/wireguard/${SERVER_WG_NIC}.conf" | cut -d ' ' -f 3 | sed -n "${CLIENT_NUMBER}"p)

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	HOME_DIR=$(getHomeDirForClient "${CLIENT_NAME}")
	rm -f "${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	wg syncconf "${SERVER_WG_NIC}" <(wg-quick strip "${SERVER_WG_NIC}")
}

function uninstallWg() {
	message="WARNING: This will uninstall WireGuard and remove all the configuration files.\n\
Please backup the /etc/wireguard directory if you want to keep your configuration files."
	prompt_message "$message" warning
	CONTINUE=""
	prompt_yes_no "Do you really want to remove WireGuard?" "n"
	if [[ "$CONTINUE" == "n" ]]; then
		prompt_message "Uninstall aborted!" info
		exit 0
	fi
	if [[ $CONTINUE == 'y' ]]; then
		checkOS

		if [[ ${OS} == 'alpine' ]]; then
			rc-service "wg-quick.${SERVER_WG_NIC}" stop
			rc-update del "wg-quick.${SERVER_WG_NIC}"
			unlink "/etc/init.d/wg-quick.${SERVER_WG_NIC}"
			rc-update del sysctl
		else
			systemctl stop "wg-quick@${SERVER_WG_NIC}"
			systemctl disable "wg-quick@${SERVER_WG_NIC}"
		fi

		if [[ ${OS} == 'ubuntu' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'debian' ]]; then
			apt-get remove -y wireguard wireguard-tools qrencode
		elif [[ ${OS} == 'fedora' ]]; then
			dnf remove -y --noautoremove wireguard-tools qrencode
			if [[ ${VERSION_ID} -lt 32 ]]; then
				dnf remove -y --noautoremove wireguard-dkms
				dnf copr disable -y jdoss/wireguard
			fi
		elif [[ ${OS} == 'centos' ]] || [[ ${OS} == 'almalinux' ]] || [[ ${OS} == 'rocky' ]]; then
			yum remove -y --noautoremove wireguard-tools
			if [[ ${VERSION_ID} == 8* ]]; then
				yum remove --noautoremove kmod-wireguard qrencode
			fi
		elif [[ ${OS} == 'oracle' ]]; then
			yum remove --noautoremove wireguard-tools qrencode
		elif [[ ${OS} == 'arch' ]]; then
			pacman -Rs --noconfirm wireguard-tools qrencode
		elif [[ ${OS} == 'alpine' ]]; then
			(cd qrencode-4.1.1 || exit && make uninstall)
			rm -rf qrencode-* || exit
			apk del wireguard-tools libqrencode libqrencode-tools
		fi

		rm -rf /etc/wireguard
		rm -f /etc/sysctl.d/wg.conf

		if [[ ${OS} == 'alpine' ]]; then
			rc-service --quiet "wg-quick.${SERVER_WG_NIC}" status &>/dev/null
		else
			# Reload sysctl
			sysctl --system

			# Check if WireGuard is running
			systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
		fi
		WG_RUNNING=$?

		if [[ ${WG_RUNNING} -eq 0 ]]; then
			prompt_message "WireGuard failed to uninstall properly." error
			exit 1
		else
			prompt_message "WireGuard uninstalled successfully." success
			exit 0
		fi
	else
		prompt_message "Removal aborted!" info
	fi
}

function manageMenu() {
	if $USE_WHIPTAIL; then
		MENU_OPTION=$(whiptail --title "WireGuard-install Menu" --menu "Select an option:" 15 60 5 \
			"1" "Add a new user" \
			"2" "List all users" \
			"3" "Revoke existing user" \
			"4" "Uninstall WireGuard" \
			"5" "Exit" 3>&1 1>&2 2>&3)
	else
		echo "Welcome to WireGuard-install!"
		echo "The git repository is available at: https://github.com/mazurky/wireguard-install"
		echo ""
		echo "It looks like WireGuard is already installed."
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a new user"
		echo "   2) List all users"
		echo "   3) Revoke existing user"
		echo "   4) Uninstall WireGuard"
		echo "   5) Exit"
		until [[ ${MENU_OPTION} =~ ^[1-5]$ ]]; do
			read -rp "Select an option [1-5]: " MENU_OPTION
		done
	fi
	case "${MENU_OPTION}" in
	1)
		newClient
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		uninstallWg
		;;
	5)
		exit 0
		;;
	*)
		prompt_message "Invalid option selected." warning
		;;
	esac
}

initialCheck

if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
	manageMenu
else
	installWireGuard
fi
