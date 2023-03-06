CC=arm-vita-eabi-gcc
CFLAGS=-Os -fno-builtin-printf -fPIC -fno-builtin-memset -Wall -Wextra -Wno-unused-variable -mcpu=cortex-a9
OBJCOPY=arm-vita-eabi-objcopy
LDFLAGS=-nodefaultlibs -nostdlib

all: kexec.bin
	
kexec.bin: standalone
	$(OBJCOPY) -O binary $^ $@
	
standalone: standalone.o
	$(CC) -o $@ $^ $(LDFLAGS) -T standalone.x
