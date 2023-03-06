CC=arm-vita-eabi-gcc
CFLAGS=-Os -fno-builtin-printf -fPIC -fno-builtin-memset -Wall -Wextra -Wno-unused-variable -mcpu=cortex-a9
OBJCOPY=arm-vita-eabi-objcopy
LDFLAGS=-nodefaultlibs -nostdlib

all: kpayload.bin
	
kpayload.bin: standalone
	$(OBJCOPY) -O binary $^ $@
	
standalone: standalone.o
	$(CC) -o $@ $^ $(LDFLAGS) -T standalone.x

clean:
	-rm kpayload.bin
	-rm standalone
	-rm standalone.o

clean_all:
	$(MAKE) -C cmep-payloads/bob clean
	make clean

full:
	make clean_all
	$(MAKE) -C cmep-payloads/bob
	make
