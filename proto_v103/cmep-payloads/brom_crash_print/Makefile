PREFIX=mep-elf-
CC=$(PREFIX)gcc
CFLAGS=-fno-delete-null-pointer-checks -nostdlib -fno-optimize-sibling-calls -mc=tiny -Os -std=gnu99 -mel
LOADER_CFLAGS=-nostdlib -mc=far -mtf -ml -Os -std=gnu99 -mel
LD=$(PREFIX)gcc
LDFLAGS=-Wl,-T main.x -nodefaultlibs -nostdlib
OBJCOPY=$(PREFIX)objcopy
OBJCOPYFLAGS=

OBJ=main.o

all: brom_crash_print.h

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.ao: %.S
	$(CC) -c -o $@ $< $(CFLAGS)

brom_crash_print.elf: $(OBJ)
	$(LD) -o $@ $^ $(LDFLAGS)

%.nmp: %.elf
	$(OBJCOPY) -O binary $< $@
	
%.h: %.nmp
	xxd -i $< > $@
	rm *.elf
	rm *.o