MODULES_DIR ?= /lib/modules/$(shell uname -r)
KERNEL_DIR ?= ${MODULES_DIR}/build

obj-m += joolif.o

joolif-objs += src/hook.o
joolif-objs += src/xlat/4to6.o
joolif-objs += src/xlat/6to4.o
joolif-objs += src/xlat/common.o
joolif-objs += src/xlat/core.o
joolif-objs += src/xlat/address.o
joolif-objs += src/xlat/ipv6_hdr_iterator.o
joolif-objs += src/xlat/packet.o
joolif-objs += src/xlat/translation_state.o
joolif-objs += src/xlat/types.o

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
