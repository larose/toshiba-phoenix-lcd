MODULE_NAME    = toshlcd
MODULE_VERSION = 1.0

DESTDIR	= 
BINDIR  = /usr/local/bin
MODDIR	= $(DESTDIR)/lib/modules
KVERS	= $(shell uname -r)
KVER	= $(KVERS)
VMODDIR = $(MODDIR)/$(KVER)
INSTDIR	= extra
KSRC	= $(VMODDIR)/build
KMODDIR	= $(KSRC)/drivers/misc/toshlcd
KDOCDIR	= $(KSRC)/Documentation/toshlcd
TBINDIR = $(DESTDIR)/$(BINDIR)
PWD	    = $(shell pwd)
TODAY	= $(shell date +%Y%m%d)
DEPMOD	= /sbin/depmod -a
RMMOD	= /sbin/modprobe -r
INSMOD	= /sbin/modprobe
MKDIR	= mkdir -p
RM      = rm -f
FIND	= find


obj-m += $(MODULE_NAME).o


all: $(MODULE_NAME).ko

clean:
	make -C $(KSRC) M=$(PWD) clean
	$(RM) -r *~ "#*#" .swp
	$(RM) -r debian/toshlcd-source *-stamp
	$(RM) -r Module.symvers Modules.symvers

install:	all
	make INSTALL_MOD_PATH=$(DESTDIR) INSTALL_MOD_DIR=$(INSTDIR) -C $(KSRC) M=$(PWD) modules_install
	$(DEPMOD)

install-script :
	install -m 655 ./$(MODULE_NAME) $(TBINDIR)

unload:
	$(RMMOD) $(MODULE_NAME) || :

load: install unload
	$(INSMOD) $(MODULE_NAME)

uninstall:	unload
	$(FIND) $(VMODDIR) -name "$(MODULE_NAME).ko" -exec $(RM) {} \;
	$(DEPMOD)

uninstall-script:
	$(RM) $(TBINDIR)/$(MODULE_NAME)    

$(MODULE_NAME).ko: $(MODULE_NAME).c
	$(MAKE) -C $(KSRC) SUBDIRS=$(PWD) modules

release: clean
	mkdir -p ../$(MODULE_NAME)-$(MODULE_VERSION)
	cp -a toshlcd.c Makefile AUTHORS ChangeLog COPYING INSTALL README toshlcd ../$(MODULE_NAME)-$(MODULE_VERSION)
	rm -f $(SRC_NAME).tar $(SRC_NAME).tar.gz
	(cd ..; tar cvf $(MODULE_NAME)-$(MODULE_VERSION).tar $(MODULE_NAME)-$(MODULE_VERSION); gzip -9 $(MODULE_NAME)-$(MODULE_VERSION).tar)

