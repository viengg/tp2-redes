#include "common.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>

#define BUFSZ 1024
#define MAXHOSTS 100
#define MAXSERVERS 20

typedef struct {
    char table[MAXHOSTS][2][BUFSZ];
} HostTable;

struct dns_data {
    int socket;
    HostTable *hosts;
};

typedef struct {
    struct sockaddr_storage storage;
    int valid;
} ServerEntry;

void usage(int argc, char **argv) {
    printf("usage: %s <server port> [startup]\n", argv[0]);
    printf("example: %s 51511\n", argv[0]);
    exit(EXIT_FAILURE);
}

// seta todos os campos de todas as entradas da tabela de hosts como nulo
void init_table(HostTable *hosts) {
    for (int i = 0; i < MAXHOSTS; i++) {
        for (int j = 0; j < 2; j++) {
            hosts->table[i][j][0] = '\0';
        }
    }
}

void att_table(HostTable *hosts, char *hostname, char *ip) {
    for (int i = 0; i < MAXHOSTS; i++) {
        // entrada vazia na tabela
        if (strcmp(hosts->table[i][0], "") == 0) {
            strcpy(hosts->table[i][0], hostname);
            strcpy(hosts->table[i][1], ip);
            printf("[add] entrada adicionada: host: %s ip: %s\n", hosts->table[i][0], hosts->table[i][1]);
            return;
        }
        // hostname ja existe na tabela
        else if (strcmp(hosts->table[i][0], hostname) == 0) {
            strcpy(hosts->table[i][0], hostname);
            strcpy(hosts->table[i][1], ip);
            printf("[add] entrada atualizada: host: %s ip: %s\n", hosts->table[i][0], hosts->table[i][1]);
            return;
        }
    }
    printf("[add] lista de hosnames/ip cheia");
}

// retorna indice na tabela de hosts se achar ou -1 se nao achar
int search_hostname(HostTable hosts, char *hostname) {
    int res = -1;
    for (int i = 0; i < MAXHOSTS; i++) {
        if (strcmp(hosts.table[i][0], hostname) == 0) {
            res = i;
            break;
        }
    }
    return res;
}

// entra em loop para recebimento e resposta de requisiçoes de outros servidores
// dns
void *wait_for_responses(void *d) {
    struct dns_data *data = (struct dns_data *)d;
    int s = data->socket;
    HostTable *hosts = data->hosts;

    char buf[BUFSZ];
    char hostname[BUFSZ];
    char ip[BUFSZ];

    struct sockaddr_storage cstorage;
    struct sockaddr *caddr = (struct sockaddr *)(&cstorage);
    socklen_t caddrlen = sizeof(cstorage);

    while (1) {
        memset(buf, 0, BUFSZ);
        memset(hostname, 0, BUFSZ);
        memset(ip, 0, BUFSZ);

        size_t count = recvfrom(s, buf, BUFSZ, 0, caddr, &caddrlen);
        printf("[recv] requisiçao recebida\n");
        size_t hostname_size = count - 1;
        memcpy(hostname, (buf + 1), hostname_size);
        hostname[hostname_size] = '\0';

        int index = search_hostname(*hosts, hostname);
        if (index == -1) {
            strcpy(ip, "-1");
        } else {
            strcpy(ip, hosts->table[index][1]);
        }

        char msg[strlen(ip) + 1];
        msg[0] = 2;
        memcpy(msg + 1, ip, strlen(ip));
        sendto(s, msg, strlen(ip) + 1, 0, caddr, caddrlen);
    }
}

// cria thread separada para tratar da comunicaçao com outros servidores
void listen_for_responses(int socket, HostTable *hosts) {
    pthread_t tid;
    struct dns_data data;
    data.socket = socket;
    data.hosts = hosts;
    pthread_create(&tid, NULL, wait_for_responses, (void *)&data);
}

// seta todas as entradas do vetor de servidores como nulo
void init_server_list(ServerEntry *servers) {
    for (int i = 0; i < MAXSERVERS; i++) {
        servers[i].valid = 0;
    }
}

// adiciona um servidor formado por um par ip/porto na lista de servidores
void link_server(ServerEntry *servers, char *ipaddr, char *port) {
    for (int i = 0; i < MAXSERVERS; i++) {
        // entrada vazia na lista
        if (servers[i].valid == 0) {
            if (0 != addrparse(ipaddr, port, &(servers[i].storage))) {
                printf("[link] erro linkagem\n");
            }
            servers[i].valid = 1;

            char addrstr[BUFSZ];
            addrtostr((struct sockaddr *)&(servers[i].storage), addrstr, BUFSZ);
            printf("[link] conectado a %s\n", addrstr);
            return;
        }
    }
    printf("[link] lista de servidores cheia\n");
}

// procura o ip de hostname na lista de servidores utilizando o socket usado
// como parametro se achar o hostname, copia seu ip para dst, caso contrario
// copia "-1"
void search_in_servers(int socket, ServerEntry *servers, char *hostname,
                       char *dst) {
    strcpy(dst, "-1");
    size_t msg_size = 1 + strlen(hostname);
    char msg[msg_size];
    msg[0] = 1;
    memcpy(msg + 1, hostname, msg_size - 1);
    
    for (int i = 0; i < MAXSERVERS; i++) {
        if (servers[i].valid) {
            socklen_t len = sizeof(servers[i].storage);
            size_t bytes_sent = sendto(socket, msg, msg_size, 0,
                                (struct sockaddr *)&(servers[i].storage), len);
            char addrstr[BUFSZ];
            addrtostr((struct sockaddr *)&(servers[i].storage), addrstr, BUFSZ);
            printf("[send] requisiçao enviada para %s: %ld bytes enviados\n", addrstr,
                   bytes_sent);

            char buf[BUFSZ];
            size_t count = recvfrom(socket, buf, BUFSZ, 0,
                            (struct sockaddr *)&(servers[i].storage), &len);
            size_t ip_size = count - 1;
            memcpy(dst, buf + 1, ip_size);
            dst[ip_size] = '\0';

            // achou um ip valido
            if (strcmp(dst, "-1") != 0) {
                return;
            }
        }
        // chegou no fim da lista de servidores linkados
        else {
            return;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) {
        usage(argc, argv);
    }

    FILE *fd = (argc == 2) ? stdin : fopen(argv[2], "r");

    struct sockaddr_storage storage;
    char *proto = "v6";
    if (0 != server_sockaddr_init(proto, argv[1], &storage)) {
        usage(argc, argv);
    }

    int s;
    s = socket(storage.ss_family, SOCK_DGRAM, 0);
    if (s == -1) {
        logexit("socket");
    }

    int enable = 1;
    if (0 != setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int))) {
        logexit("setsockopt");
    }

    struct sockaddr *addr = (struct sockaddr *)(&storage);
    if (0 != bind(s, addr, sizeof(storage))) {
        logexit("bind");
    }

    char addrstr[BUFSZ];
    addrtostr(addr, addrstr, BUFSZ);
    printf("bound to %s, waiting connections\n", addrstr);

    HostTable hosts;
    init_table(&hosts);
    ServerEntry servers[MAXSERVERS];
    init_server_list(servers);
    char args[3][BUFSZ];

    listen_for_responses(s, &hosts);

    while (1) {
       if(fscanf(fd, "%s", args[0]) != 1){
           exit(EXIT_SUCCESS);
       }

        if (strcmp(args[0], "add") == 0) {
            fscanf(fd, "%s", args[1]);
            fscanf(fd, "%s", args[2]);
            att_table(&hosts, args[1], args[2]);

        } else if (strcmp(args[0], "search") == 0) {
            fscanf(fd, "%s", args[1]);
            
            int index = search_hostname(hosts, args[1]);
            // achou o ip localmente
            if (index >= 0) {
                printf("[search] endereço de ip de %s: %s\n", args[1],
                       hosts.table[index][1]);
            //existe pelo menos um servidor conectado
            } else if (servers[0].valid){
                printf("[search] nao achou o endereço de %s localmente\n", args[1]);

                char ip[BUFSZ];
                int socket_req = socket(storage.ss_family, SOCK_DGRAM, 0);
                search_in_servers(socket_req, servers, args[1], ip);
                close(socket_req);

                if (strcmp(ip, "-1") == 0) {
                    printf("[search] nao achou o endereço de %s nos servidores linkados\n", args[1]);
                } else {
                    printf("[search] endereço de ip de %s: %s\n", args[1], ip);
                }
            }
            else{
                printf("[search] nao achou o endereço de %s localmente\n", args[1]);
                printf("[search] nao existem servidores para pesquisar\n");
            }
            
        } else if (strcmp(args[0], "link") == 0) {
            fscanf(fd, "%s", args[1]);
            fscanf(fd, "%s", args[2]);
            link_server(servers, args[1], args[2]);
        }
        else {
            printf("comando nao reconhecido\n");
        }
    }

    exit(EXIT_SUCCESS);
}