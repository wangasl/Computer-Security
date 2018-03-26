# Shulin Wang
# HW09
# ECE 404

# This is the shell script that complete specific tasks



# Place no restriction on outbound packets
iptables -I OUTPUT 1 -j ACCEPT

# Block a list of specific ip addresses
# create a list of IP
list_IP=( "128.12.1.12" "128.23.2.23" "128.18.1.18" )
for ip in ${list_IP[@]}
do
	iptables -A INPUT -s $ip -j DROP	
done

# Block computer from being pinged
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Set up port-forwarding from an unused port
# Open port 6000 
iptables -A INPUT -p tcp --dport 6000 -j ACCEPT
# Forward it to port 22
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 6000 -j REDIRECT --to-port 22

# Allow for SSH access from only ecn domain
# Reject all ssh access
iptables -A INPUT -p tcp --dport 22 -j REJECT
# Allow only ecn domain
iptables -A INPUT -s ecn.purdue.edu -p tcp --dport 22 -j ACCPET

# Allow only a single IP address
# Reject all ip address to HTTPD(port 80)
iptables -A INPUT -p tcp --dport 80 -j REJECT
# Allow only specific IP
iptables -A INPUT -s 128.12.1.12 -p tcp --dport 80 -j ACCPET

# Permit Auth/Ident(port 113)
iptables -A INPUT -p tcp --dport 113 -j ACCEPT
