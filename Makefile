default:	build

NGINX_ROOT = ../nginx

.PHONY: clean configure build start stop test curl

src/http_auth_header_parser.c: src/http_auth_header_parser.peg
	cd src; ../../packcc/build/gcc/debug/bin/packcc -a -l http_auth_header_parser.peg

clean:
	if [ -e $(NGINX_ROOT)/Makefile ]; then \
		$(MAKE) -C $(NGINX_ROOT) clean;    \
	fi
	rm -rf root nginx.core

configure: stop
	cd $(NGINX_ROOT) && CFLAGS="-Wno-error=cast-function-type -O0 -g" ./configure --with-debug --add-module=${CURDIR}/src

build: stop src/http_auth_header_parser.c
	$(MAKE) -C $(NGINX_ROOT) build

root:
	mkdir -p root/logs

root/debug.conf: root debug.conf
	cp ${CURDIR}/debug.conf root/debug.conf

root/logs: root
	mkdir -p root/logs

start:	build root/logs root/debug.conf
	rm -f root/logs/error.log
	$(NGINX_ROOT)/objs/nginx -p ${CURDIR}/root -c debug.conf

stop:
	if [ -e ${CURDIR}/root/logs/nginx.pid ]; then \
		if [ -x $(NGINX_ROOT)/objs/nginx ]; then \
			$(NGINX_ROOT)/objs/nginx -s stop -p ${CURDIR}/root -c debug.conf; \
		fi ; \
	fi

test: start curl stop

curl:
	python3 ../../sasl/http_sasl.py
