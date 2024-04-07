all:
	gcc -o client simDNSclient.c
	gcc -o server simDNSserver.c
	sudo setcap cap_net_raw,cap_net_admin=eip server
	sudo setcap cap_net_raw,cap_net_admin=eip client

clean:
	rm -f client server