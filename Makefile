KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build
MY_CFLAGS += -g -DDEBUG

obj-m += gooroom_interp_lock.o
#obj-m += shebang_python.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

debug:
	make -C $(KERNEL_PATH) M=$(PWD) modules EXTRA_CFLAGS="$(MY_CFLAGS)"

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
