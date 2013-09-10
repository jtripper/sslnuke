all:
	gcc -o sslnuke src/conn_list.c src/util.c src/main.c src/ssl.c src/parse_incoming.c -lssl -lcrypto

clean:
	rm sslnuke
