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

and adjust the ``TransparentProxy`` and ``Listen`` settings accordingly:

::

 # head /usr/local/etc/proxsmtpd.conf
 TransparentProxy: full
 Listen: 0.0.0.0:10025
 FilterType: smtp
 FilterCommand: 192.168.0.100 # or 127.0.0.1 for haproxy

High volume
-----------

In order to handle many connections and high throughput, make sure that max open
files is high enough and raise the ``MaxConnections`` setting.

::

 # grep nofile /etc/security/limits.conf 
 *                soft    nofile          10000
 *                hard    nofile          10000
 # ulimit -n 10000
 # grep MaxConnections /usr/local/etc/proxsmtpd.conf 
 MaxConnections: 3000

If disk IOPS becomes a bottleneck, you can use a memory filesystem

::

 # grep tmpfs /etc/fstab
 tmpfs   /tmp         tmpfs   nodev,nosuid,size=2G          0  0
 
or increase the write cache size
 
::
 
 # grep sysctl /etc/rc.local
 sysctl vm.dirty_background_ratio=50
 sysctl vm.dirty_ratio=80
 sysctl vm.dirty_expire_centisecs=30000
 sysctl vm.dirty_writeback_centisecs=3000

Multiple Halon nodes
--------------------

The easiest way to have a transparent setup with multiple Halon nodes, is to install haproxy:

::

 # tail /etc/haproxy/haproxy.cfg
 frontend localnodes
        bind *:20025
        mode tcp
        default_backend halons
 backend halons
        mode tcp
        balance roundrobin
        option smtpchk
        server out1 10.0.0.2:10025 check
        server out2 10.0.0.3:10025 check

and make proxsmtp connect to haproxy

::

 # grep htons proxsmtp/src/proxsmtpd.c
	remote.sin_port = htons(20025);
 # grep Filter /usr/local/etc/proxsmtpd.conf
 FilterType: smtp
 FilterCommand: 127.0.0.1
