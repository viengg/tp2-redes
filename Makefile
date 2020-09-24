all:
	gcc -Wall -c common.c
	gcc -Wall -pthread servidor_dns.c common.o -o servidor_dns

clean:
	rm common.o servidor_dns 
