#!/bin/bash

### BEGIN INIT INFO
# Provides:          anonsurf
# RequiR-Start:
# RequiR-Stop:
# Should-Start:
# Default-Start:
# Default-Stop:
# Short-Description: Transparent Proxy through TOR.
### END INIT INFO
#
# Devs:
# Lorenzo 'EclipseSpark' Faletra <eclipse@frozenbox.org>
# Lisetta 'Sheireen' Ferrero <sheireen@frozenbox.org>
# Francesco 'mibofra'/'Eli Aran'/'SimpleSmibs' Bonanno <mibofra@ircforce.tk> <mibofra@frozenbox.org>
#
#
# anonsurf is free software: you can Ristribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# You can get a copy of the license at www.gnu.org/licenses
#
# anonsurf is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Parrot Security OS. If not, see <http://www.gnu.org/licenses/>.

# Colorize the environment
export B=$'\033[1;94m'
export G=$'\033[1;92m'
export R=$'\033[1;91m'
export RST=$'\033[1;00m'

# Destinations you don't want routed through Tor
TOR_EXCLUDE="192.168.0.0/16 172.16.0.0/12 10.0.0.0/8"

# The UID Tor runs as
# change it if, starting tor, the command 'ps -e | grep tor' returns a different UID
TOR_UID="debian-tor"

# Tor's TransPort
TOR_PORT="9040"

# Some dangerous applications
DANGEROUS_APPLICATIONS="chrome dropbox iceweasel skype icedove thunderbird firefox firefox-esr chromium xchat hexchat transmission steam"

# Some dangerous services
DANGEROUS_SERVICES="dnsmasq nscd resolvconf"

# Cache elements to clear
DANGEROUS_CACHE_ELEMENTS="adobe_reader.cache chromium.cache chromium.current_session chromium.history elinks.history emesene.cache epiphany.cache firefox.url_history"

# FrozenBox DNS
DNS="nameserver 127.0.0.1\nnameserver 92.222.97.144\nnameserver 92.222.97.145"

# Iptables save location
IPTABLES="/etc/network/iptables.rules" 


###
# Display
###

# Reset and display the banner
function display_banner 
{
reset
banner="
$B Parrot AnonSurf Module (v 2.3) - Developed by : $RST
	-Lorenzo   \"Palinuro\"  Faletra <palinuro@parrotsec.org>
	-Lisetta   \"Sheireen\"  Ferrero <sheireen@parrotsec.org>
	-Francesco \"Mibofra\"   Bonanno <mibofra@parrotsec.org>
	 and a huge amount of Caffeine + some GNU/GPL v3 stuff"
echo -e "$banner\n"
}

# Diplay the commands
function display_commands
{
commands="
	$R┌──[$G$USER$YELLOW@$B`hostname`$R]─[$G$PWD$R] 
	$R└──╼ \$$G"" anonsurf $R{$G""start$R|$G""stop$R|$G""restart$R|$G""change$R""$R|$G""status$R""}
	$R start$B	  -$G Start system-wide TOR tunnel
	$R stop$B	  -$G Stop anonsurf and return to clearnet
	$R restart$B  -$G Combines \"stop\" and \"start\" options
	$R change$B	  -$G Restart TOR to change identity
	$R status$B	  -$G Check if AnonSurf is working properly
	$R myip$B	  -$G Check your ip and verify your tor connection

	----[ I2P related features ]----
	$R starti2p$B -$G Start i2p services
	$R stopi2p$B  -$G Stop  i2p services$RST"
echo -e -n "$commands\n\n"
}


###
# Service Management
###

# Stop the service passed in argument
function services_stop
{
	echo -e -n "$B[$G*$B] Stopping service $1\n"
	eval "service $1 stop &> /dev/null"
	if [ $? -eq 0 ]; then
		echo -e " $G●$RST $1 stopped\n"
	else
		echo -e "$G[$R!$G]$R $1 is already stopped\n"
	fi	
}

# Restart the service passed in argument
function services_restart
{
	echo -e -n "$B[$G*$B] Restarting service $1\n"
	eval "service $1 restart &> /dev/null"
	echo -e " $G●$RST $1 restarted\n"
}

# Display the status passed in argument
function services_check
{
	echo -e "\n$B* $1$RST"
	if [  `service $1 status 2>/dev/null | wc -l` != 0 ]; then
		(service $1 status | sed -n 2,3p)
	else
		echo -e "   $G[$R!$G]$R service not found !"
	fi

}


###
# Functions : require_root - notify - processing - clean_dhcp - set_iptables - init
###

# Make sure only root can run this script
function require_root
{
	if [ $(id -u) -ne 0 ]; then
		echo -e -e "$G[$R!$G]$R Anonsurf must be run as root !$RST\n"
		exit 1
	fi
}

# Emit an alert to user
function notify 
{	
	# notify-send only working with non-root user
	if [ -e /usr/bin/notify-send ]; then

		if [ $(id -u) -ne 0 ]; then # ok, display the notification
			/usr/bin/notify-send "Anonsurf" "$1"

		else # grep and send the notification to main user
			MAINUSER=$(cat /etc/passwd|grep 1000|sed "s/:.*$//g")
			su $MAINUSER -c $"notify-send \"AnonSurf\" \"$1\""
		fi

	fi
}
export notify


# Processing and display command result
function processing
{ 
	echo -e -n "$B[$G*$B] $1 $RST\n"
	eval "$2 2> /dev/null"
	echo -e "$G ●$RST $3\n"
}

# Release DHCP address
function clean_dhcp 
{
	dhclient -r
	rm -f /var/lib/dhcp/dhclient*
	echo -e -n "$B[$G*$B] DHCP address released"
}


# Set the iptables rules
function set_iptables
{
	echo -e -n "$B[$G*$B] Redirect all traffic throught Tor \n"

	# Set iptables nat
	iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN

	# Set dns Redirect
	iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
	iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53
	iptables -t nat -A OUTPUT -p udp -m owner --uid-owner $TOR_UID -m udp --dport 53 -j 	REDIRECT --to-ports 53
	
	# Resolve .onion domains mapping 10.192.0.0/10 address space
	iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports $TOR_PORT
	iptables -t nat -A OUTPUT -p udp -d 10.192.0.0/10 -j REDIRECT --to-ports $TOR_PORT
	
	# Exclude local addresses
	for NET in $TOR_EXCLUDE 127.0.0.0/9 127.128.0.0/10; do
		iptables -t nat -A OUTPUT -d $NET -j RETURN
		iptables -A OUTPUT -d "$NET" -j ACCEPT
	done
	
	# Redirect all other output through TOR	
	iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TOR_PORT
	iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports $TOR_PORT
	iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports $TOR_PORT
	
	# Accept already established connections
	iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	
	# Allow only tor output
	iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT
	iptables -A OUTPUT -j REJECT

	echo -e "$G ●$RST All traffic was redirected throught Tor\n"
}

# Init before start or stop
function init 
{
	# Kill dangerous applications
	cmd="killall -q $DANGEROUS_APPLICATIONS"
	processing "Killing dangerous applications" "$cmd" "Dangerous applications killed"

	# Kill dangerous cache elements
	cmd="bleachbit -c $DANGEROUS_CACHE_ELEMENTS 1> /dev/null"
	processing "Cleaning some dangerous cache elements" "$cmd" "Cache cleaned"

}


###
# I2P : starti2p - stopi2p
###

# start I2P service
function starti2p 
{
	echo -e "$G[$B!$G]$B STARTING I2P SERVICES :$RST\n"

	# check if tor is not running before continue
	if [ `ps -e | grep tor | wc -l` = 1 ]; then
		echo -e "$G[$R!$G]$R Tor must be stopped !"
	else

		# Start 2IP deamon
		cmd="sudo -u i2psvc i2prouter start > /dev/null"
		processing "Start I2P daemon" "$cmd" "I2P daemon started"
		sleep 10

		echo "I2P daemon started - localhost:7657"		
		notify "I2P daemon started - localhost:7657"

	fi
}

# stop I2P service
function stopi2p 
{
	echo -e "$G[$B!$G]$B STOPPING I2P SERVICES :$RST\n"

	# stopping I2P daemon
	cmd="sudo -u i2psvc i2prouter stop > /dev/null"		
	processing "Stopping I2P daemon" "$cmd" "I2P daemon stopped"

	notify "I2P daemon stopped"
}



###
# Global Proxy : start - stop - check_ip - change - status
###


# Start Tor Global Proxy
function start 
{	
	echo -e "$G[$B!$G]$B STARTING ANONIMOUS MODE :$RST\n"

	# Check if Tor is already started
	if [ `ps -e | grep tor | wc -l` = 1 ]; then

		echo -e "$B[$G*$B] Tor seems already running\n"
		notify "Tor seems already running"

		# Check if connected trough Tor (or reload Tor service)
		check_ip "safe"
	else

		echo -e "$B[$R*$B] Tor is not running:$G starting it$B for you\n"
		
		# Stop the following services
		services_stop "nscd"
		services_stop "resolvconf"
		services_stop "dnsmasq"
		
		# Kill the dangerous services
		cmd="killall $DANGEROUS_SERVICES"
		processing "Killing dangerous services" "$cmd" "Dangerous applications killed"


		# Starting resolvconf and tor services
		cmd="service resolvconf start ; systemctl start tor"
		processing "Starting tor service" "$cmd" "Tor service started"
		sleep 8 # Wait for ensure tor running in right way

		if ! [ -f $IPTABLES ]; then
			# Saving possible user iptables rules
			cmd="iptables-save > $IPTABLES"
			processing "Saving iptables rules" "$cmd" "Saved iptables rules"
		fi
	
		# Flush current iptables rules
		cmd="iptables -F ; iptables -t nat -F"
		processing "Delete all Tor iptables rules" "$cmd" "All Tor iptables rules deleted"
		sleep 2 # Wait for ensure iptables rules is removed.

		# Use Frozenbox DNS
		cmd="mv /etc/resolv.conf /etc/resolv.conf.bak ; echo -e '$DNS' > /etc/resolv.conf"
		processing "Use Tor with FrozenDNS" "$cmd" "Modified resolv.conf"

		# Set the right iptables
		set_iptables
		sleep 2

		# Check if connected trough Tor (or reload Tor service)
		check_ip "safe" 

		notify "Global Anonymous Proxy Activated"

	fi
}

# Stop Tor Global Proxy
function stop 
{
	echo -e "$G[$B*$G]$B STOPPING ANONYMOUS MODE :$RST\n"

	# Check if Tor is already stopped
	if [ `ps -e | grep tor | wc -l` = 0 ]; then

		echo -e "$B[$G*$B] Tor is already stopped\n"
		notify " Tor is already stopped"
		check_ip

	else

		echo -e "$B[$R*$B] Tor is running:$G stopping it$B for you\n"
	

		# Flush current iptables rules
		cmd="iptables -F ; iptables -t nat -F"
		processing "Delete all Tor iptables rules" "$cmd" "All Tor iptables rules deleted"
		sleep 2 # Wait for ensure iptables rules is removed.
	
		if [ -f $IPTABLES ]; then
			# Restaure all iptables rules	
			cmd="iptables-restore < $IPTABLES ; rm $IPTABLES"
			processing "Restore all iptables rules" "$cmd" "All iptables rules restored"
		fi

		if [ -e /etc/resolv.conf.bak ]; then
			# Restore all DNS rules	
			cmd="mv /etc/resolv.conf.bak /etc/resolv.conf"
			processing "Restore DNS service" "$cmd" "DNS service restored"
		fi

		# Stop TOR service	
		cmd="service tor stop"
		processing "Stopping Tor service" "$cmd" "Tor service stopped"
		sleep 4

		# Restart the following services
		services_restart "resolvconf"
		services_restart "dnsmasq"
		services_restart "nscd"

		# Check if disconnected trough TOR
		check_ip

		notify "Global Anonymous Proxy Desactivated"
	fi
}

# Check Tor connectivity using ip.frozenbox.org
function check_ip 
{
	# get the user ip and country code using ip.frozenbox.org
   	data=$( wget -qO- --tries=4 http://ip.frozenbox.org/ )

	# Check the result
	if [[ $data == *"T1" || $data == *"XX" ]]; then # T1 or XX, client is connected throught Tor
		echo -e -n "$B[$G*$B] Your public ip is: "
		echo $data
		echo -e " $G●$RST Connected throught Tor\n"
		notify "ip: $data"

	elif [ -z "$data" ]; then # ip.frozenbox.org does not respond 
		echo -e "$R$G[$R!$G]$R Your public ip is: unknown $RST"
		echo -e " $R●$RST Check it manually:\n - ip.frozenbox.org\n - check.torproject.org\n"
		notify "ip: unknown"

	else # another country code or empty result

		if [ -z $1 ]; then #common mode or anonsurf stop
			echo -e -n "$B[$G*$B] Your public ip is: "
			echo $data
			echo -e " $R●$RST You seems not be connected throught Tor\n"
			notify "ip: $data"

		else # safe mode, emit an alert and reload
			echo -e "$R$G[$R!$G]$R Connection failed, retry ...\n"
			change "silent" # fast reload
		fi

	fi
}


# Change Tor nodes
function change 
{
	if [ -z "$1" ]; then # common mode or anonsurf change

		# check if Tor is started before change node
		if ! pgrep -x "tor" > /dev/null; then # not started
			echo -e "$G[$R!$G]$R Tor is not started\n"
			notify "Tor is not started"

		else # started
			notify "Change identity"
			service tor reload
			sleep 8
			echo -e "$B[$G*$B] Changing Tor node"
			echo -e " $G●$RST Tor daemon reloaded and forced to change nodes\n"
			
			# Check if connected trough Tor (or reload Tor service)
			check_ip "safe"
		fi

	else # silent mode, fast service restart
			service tor reload
			sleep 4

			# Check if connected trough Tor (or reload Tor service)
			check_ip "safe"
	fi
}

# Check the current Anonsurf status
function status 
{
	# display Tor log
	echo -e "$B[$G*$B] Display Tor logs$RST"
	sleep 2
	journalctl -u tor@default --reverse # tor logs, most recent at top

	# display iptables
	echo -e "\n$B[$G*$B] Display iptables$RST"
	sleep 2
	iptables -S
	sleep 1
	iptables -L 
	
	# display nameservers
	echo -e "\n$B[$G*$B] Display nameservers$RST"
	sleep 2

	if [ ! -s /etc/resolv.conf ]; then # /etc/resolv.conf is empty
		echo -e "   $G[$R!$G]$R /etc/resolv.conf is empty !"
	else # display /etc/resolv.conf
		cat /etc/resolv.conf
	fi

	# display the service status
	echo -e "\n$B[$G*$B] Display services state$RST"
	sleep 2

	# check all service status
	services_check "tor"
	services_check "dnsmasq"
	services_check "nscd"
	services_check "resolvconf"

}


###
# Entry point 
###

# Display the banner in all case
display_banner

# Get the user choice
case "$1" in
	start)
		require_root
		init
		start
	;;
	stop)
		require_root
		init
		stop
	;;
	change)
		require_root
		change
	;;
	status)
		require_root
		status
	;;
	myip)
		check_ip
	;;
	starti2p)
		starti2p
	;;
	stopi2p)
		stopi2p
	;;
	restart)
		require_root
		init
		stop
		sleep 2
		init
		start
	;;
    *)
		display_commands
		exit 1
	;;
esac

# At the end 
sleep 4
echo -e $RST
exit 0
