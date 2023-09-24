MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

obj-m += joolif.o

joolif-objs += hook.o
joolif-objs += xlat/4to6.o
joolif-objs += xlat/6to4.o
joolif-objs += xlat/common.o
joolif-objs += xlat/core.o
joolif-objs += xlat/address.o
joolif-objs += xlat/ipv6_hdr_iterator.o
joolif-objs += xlat/packet.o
joolif-objs += xlat/translation_state.o
joolif-objs += xlat/types.o

all:
	make -C ${KERNEL_DIR} M=$$PWD
modules:
	make -C ${KERNEL_DIR} M=$$PWD $@
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@
install: modules_install
	depmod
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@
debug:
	make CFLAGS_MODULE+=-DDEBUG all
insert:
	sudo insmod joolif.ko
remove:
	-sudo rmmod joolif
