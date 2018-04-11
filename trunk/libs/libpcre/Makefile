SRC_NAME=pcre


all: config_test
	$(MAKE) -C $(SRC_NAME)

config_test:
	( if [ -f ./config_done ]; then \
		echo "the same configuration"; \
	else \
		make configure && touch config_done; \
	fi )

download:
	( if [ -d ./$(SRC_NAME) ]; then \
		echo "pcre exist!"; \
	else \
		git clone https://github.com/svn2github/pcre.git $(SRC_NAME); \
	fi )

configure: download
	( cd $(SRC_NAME) ; \
	./autogen.sh ; \
	./configure \
		--prefix=$(STAGEDIR) \
		--enable-static \
		--disable-shared \
		--disable-debug-mode \
		--enable-pcre16 \
		--enable-pcre32 \
		--enable-unicode-properties \
		--enable-newline-is-any \
		--enable-jit \
		--disable-pcregrep-jit \
		--host=$(HOST_TARGET) \
		--build=$(HOST_BUILD) ; \
	)

clean:
	if [ -f $(SRC_NAME)/Makefile ] ; then \
		$(MAKE) -C $(SRC_NAME) distclean ; \
	fi ; \
	rm -f config_done

install:
	$(MAKE) -C $(SRC_NAME) install DESTDIR=""

romfs:

