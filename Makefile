TARGET_MODULE:=smetest
BUILDSYSTEM_DIR:=<path to kernel tree>
PWD:=$(shell pwd)

obj-m := $(TARGET_MODULE).o

all :
# run kernel build system to make module
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(BUILDSYSTEM_DIR) M=$(PWD) clean

