#!/bin/sh
bind_address=$(nvram get dnsproxy_bind)
bind_port=$(nvram get dnsproxy_port)
remote_ip=$(nvram get dnsproxy_remote_ip)
remote_port=$(nvram get dnsproxy_remote_port)
remote_tcp=$(nvram get dnsproxy_remote_tcp)
hosts=$(nvram get dnsproxy_hosts)


gfwhosts="/etc/storage/dnsmasq/gfwhosts"

if [ "x" == "x$remote_ip" ]; then
	remote_ip="8.8.8.8";
fi

if [ "x" == "x$remote_port" ]; then
	remote_port="53";
fi

if [ "x1" == "x$remote_tcp" ]; then
	remote_tcp="-T";
else
	remote_tcp="";
fi

if [ -f $gfwhosts ]; then
	hosts=$gfwhosts;
fi

if [ "x" == "x$hosts" ]; then
	hosts="/dev/null";
fi

func_start(){
	dnsproxy -d $remote_tcp -R $remote_ip -P $remote_port -f $hosts
}

func_stop(){
	killall -q dnsproxy
}

case "$1" in
start)
    func_start
    ;;
stop)
    func_stop
    ;;
restart)
    func_stop
    func_start
    ;;
*)
    echo "Usage: $0 { start | stop | restart }"
    exit 1
    ;;
esac
