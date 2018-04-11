SRC_NAME=minivtun-git/src

CFLAGS += -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections

THISDIR = $(shell pwd)

all:	config_test
	$(MAKE) -C $(SRC_NAME)

config_test:
	( if [ -f ./config_done ]; then \
		echo "the same configuration"; \
	else \
		make configure && touch config_done; \
	fi )


download:
	( if [ -d ./minivtun-git ]; then \
		echo "minivtun exist"; \
	else \
		git clone https://github.com/rssnsj/minivtun.git minivtun-git; \
	fi )


configure:
	make download;


clean:
	if [ -f $(SRC_NAME)/Makefile ] ; then \
		$(MAKE) -C $(SRC_NAME) distclean ; \
	fi ; \
	rm -f config_done

romfs:
	$(ROMFSINST) $(THISDIR)/$(SRC_NAME)/minivtun  /usr/sbin/minivtun

