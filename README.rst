Transparent SMTP proxy http://wiki.halon.io/Proxy for Halon's email gateway, fork of http://thewalter.net/stef/software/proxsmtp/

Installation on Debian
----------------------
::

  apt-get install libcap-dev
  sh autogen.sh
  make
  
Fully transparent
-----------------

Add the following to ``/etc/rc.local``
::

 modprobe nf_conntrack_ipv4
 iptables -t mangle -N DIVERT
 iptables -t mangle -A DIVERT -j MARK --set-mark 0x01/0x01
 iptables -t mangle -A DIVERT -j ACCEPT
 iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
 iptables -t mangle -A PREROUTING -p tcp --dport 25 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 10025
 ip route flush table 100
 ip rule add fwmark 1 lookup 100
 ip route add local 0.0.0.0/0 dev lo table 100
 echo 0 > /proc/sys/net/ipv4/conf/lo/rp_filter
 echo 1 > /proc/sys/net/ipv4/ip_forward

and set the ``TransparentProxy`` setting to ``full``.

High volume
-----------

In order to handle many connections and high throughput, make sure that max open
files is high enough and raise the ``MaxConnections`` setting. If disk IOPS becomes
a bottleneck then a memory filesystem can be used.

::

 # grep nofile /etc/security/limits.conf 
 nobody           soft    nofile          10000
 nobody           hard    nofile          10000
 *                soft    nofile          10000
 *                hard    nofile          10000
 # ulimit -n 10000
 # grep MaxConnections /usr/local/etc/proxsmtpd.conf 
 MaxConnections: 3000
 # grep tmpfs /etc/fstab
 tmpfs   /tmp         tmpfs   nodev,nosuid,size=2G          0  0

