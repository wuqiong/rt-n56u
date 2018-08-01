 #!/bin/sh


server_name="flashwifi.csdc.io"

server_ip=`ping -c1 -q $server_name | grep 'PING' | cut -d \  -f 3 | egrep -o '[0-9.]+'`
ipset add ss_spec_dst_bp $server_ip > /dev/null 2>&1

#update online config
wget --no-check-certificate  -O -  https://$server_name/flashwifi-config-latest.sh | bash


nvram commit
