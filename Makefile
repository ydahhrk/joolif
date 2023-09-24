all:
	make -C mod
	make -C usr
clean:
	make -C mod clean
	make -C usr clean
insert:
	make -C mod insert
remove:
	make -C mod remove
test:
	make remove
	make insert
	usr/joolif siit0 pool6 1:2::/92
	usr/joolif siit0 pool6791v6 2001:db8::1
	usr/joolif siit0 pool6791v4 192.0.2.1
	usr/joolif siit0 amend-udp-checksum-zero 1
	usr/joolif siit0 amend-udp-checksum-zero 0
	usr/joolif siit0 lowest-ipv6-mtu 1500
	-usr/joolif siit0 pool6 2001:db8::/8
	-usr/joolif siit0 lowest-ipv6-mtu 123
	sudo dmesg -c