# by RouterOS 6.47

/ip firewall filter
add action=jump chain=input comment="jump to ICMP filters" in-interface-list=\
    global jump-target=icmp protocol=icmp
add action=jump chain=input comment=\
    "in hook all new connections from internet" connection-state=new \
    dst-address-list=wan_ip in-interface-list=global jump-target=in-global
add action=jump chain=in-global comment="in hook admins new connections" \
    connection-state=new jump-target=in-admins src-address-list=admins
add action=accept chain=in-admins comment="defconf: accept new control from ad\
    mins (this ports are just for access to this device)" connection-state=\
    new dst-port=22,80,443,8291,8728,8729 protocol=tcp
add action=drop chain=in-admins comment=\
    "defconf: drop all another from admins"
add action=drop chain=in-global comment="drop total for ssh bruteforces" \
    src-address-list=ssh_blacklist
add action=drop chain=in-global comment="drop total for port scanners" \
    src-address-list=port_scanners
add action=add-src-to-address-list address-list=port_scanners \
    address-list-timeout=2w chain=in-global comment=\
    "drop total for port scanners" log=yes log-prefix=FAIL2BAN protocol=tcp \
    psd=21,3s,3,1
add action=add-src-to-address-list address-list=ssh_blacklist \
    address-list-timeout=1w3d chain=in-global comment="drop ssh bruteforces" \
    connection-state=new dst-port=22,8291 log=yes log-prefix=FAIL2BAN \
    protocol=tcp src-address-list=ssh_stage3
add action=add-src-to-address-list address-list=ssh_stage3 \
    address-list-timeout=1m chain=in-global comment="drop ssh bruteforces" \
    connection-state=new dst-port=22,8291 protocol=tcp src-address-list=\
    ssh_stage2
add action=add-src-to-address-list address-list=ssh_stage2 \
    address-list-timeout=1m chain=in-global comment="drop ssh bruteforces" \
    connection-state=new dst-port=22,8291 protocol=tcp src-address-list=\
    ssh_stage1
add action=add-src-to-address-list address-list=ssh_stage1 \
    address-list-timeout=1m chain=in-global comment="drop ssh bruteforces" \
    connection-state=new dst-port=22,8291 protocol=tcp
add action=accept chain=in-global comment=\
    "defconf: accept ssh and winbox in global (backdoor access, guarded)" \
    connection-state=new dst-port=22,8291 protocol=tcp
add action=accept chain=in-global comment="allow ip's that's ever had a succes\
    ful connection (It need to setup in PPP profile!)" dst-port=1701,500,4500 \
    protocol=udp src-address-list=l2tp_success tcp-flags=""
add action=accept chain=in-global comment="defconf: accept L2TP+IPSec in" \
    connection-state=new protocol=ipsec-esp src-address-list=l2tp_success
add action=accept chain=in-global comment="defconf: accept L2TP+IPSec in" \
    connection-state=new protocol=ipsec-ah src-address-list=l2tp_success
add action=reject chain=in-global comment="drop l2tp bruteforces" dst-port=\
    1701,500,4500 protocol=udp reject-with=icmp-admin-prohibited \
    src-address-list=l2tp_blacklist
add action=drop chain=in-global comment="drop l2tp bruteforces" protocol=\
    ipsec-esp src-address-list=l2tp_blacklist
add action=drop chain=in-global comment="drop l2tp bruteforces" protocol=\
    ipsec-ah src-address-list=l2tp_blacklist
add action=add-dst-to-address-list address-list=l2tp_blacklist \
    address-list-timeout=3d chain=output comment="drop l2tp bruteforces" \
    content="M=bad" dst-address-list=l2tp_stage2 log=yes log-prefix=FAIL2BAN
add action=add-dst-to-address-list address-list=l2tp_stage2 \
    address-list-timeout=1m chain=output comment="drop l2tp bruteforces" \
    content="M=bad" dst-address-list=l2tp_stage1
add action=add-dst-to-address-list address-list=l2tp_stage1 \
    address-list-timeout=1m chain=output comment="drop l2tp bruteforces" \
    content="M=bad"
add action=accept chain=in-global comment="defconf: accept L2TP+IPSec in" \
    connection-state=new dst-port=1701,500,4500 protocol=udp
add action=accept chain=in-global comment="defconf: accept L2TP+IPSec in" \
    connection-state=new protocol=ipsec-esp
add action=accept chain=in-global comment="defconf: accept L2TP+IPSec in" \
    connection-state=new protocol=ipsec-ah
add action=drop chain=in-global comment="drop all another"
add action=accept chain=icmp comment="allow echo request" icmp-options=8:0 \
    protocol=icmp
add action=accept chain=icmp comment="echo reply" icmp-options=0:0 protocol=\
    icmp
add action=accept chain=icmp comment="net unreachable" icmp-options=3:0 \
    protocol=icmp
add action=accept chain=icmp comment="host unreachable" icmp-options=3:1 \
    protocol=icmp
add action=accept chain=icmp comment=\
    "host unreachable fragmentation required" icmp-options=3:4 protocol=icmp
add action=accept chain=icmp comment="allow time exceed" icmp-options=11:0 \
    protocol=icmp
add action=accept chain=icmp comment="allow parameter bad" icmp-options=12:0 \
    protocol=icmp
add action=drop chain=icmp comment="deny all other types"
add action=accept chain=input comment=\
    "defconf: accept established,related,untracked" connection-state=\
    established,related,untracked
add action=drop chain=input comment="defconf: drop invalid" connection-state=\
    invalid
add action=accept chain=input comment="defconf: accept ICMP" protocol=icmp
add action=accept chain=input comment=\
    "defconf: accept to local loopback (for CAPsMAN)" dst-address=127.0.0.1
add action=accept chain=input comment="accept all traffic from vpn-channels" \
    in-interface-list=vpn-region
add action=accept chain=input comment=\
    "accept all traffic from local interfaces" in-interface-list=local
add action=drop chain=input comment="drop all other input"
add action=accept chain=forward comment="defconf: accept in ipsec policy" \
    ipsec-policy=in,ipsec
add action=accept chain=forward comment="defconf: accept out ipsec policy" \
    ipsec-policy=out,ipsec
add action=fasttrack-connection chain=forward comment="defconf: fasttrack" \
    connection-state=established,related
add action=accept chain=forward comment=\
    "defconf: accept established,related, untracked" connection-state=\
    established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" \
    connection-state=invalid
add action=drop chain=forward comment=\
    "defconf: drop all from global not DSTNATed" connection-nat-state=!dstnat \
    connection-state=new in-interface-list=global
