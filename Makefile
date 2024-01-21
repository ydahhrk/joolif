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
