/*
*Project: Skener sieťových služieb
*author: Barbora Nemčeková <xnemce06@stud.fit.vutbr.cz>
*date: 15.04.2019
*
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h> 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "header.h"
#define __USE_BSD
#define __FAVOR_BSD
#define DATA "datastring"
#define ETHER_ADDR_LEN 

struct pseudoTCPpacket{
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

void packetHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet ){
     /*ether_header *eth = packet;
     iphdr *ip = packet + sizeof(ether_header);
     tcphdr *tcp = ip + sizeof(iphdr);*/
     const struct ether_header *eth;
     const struct iphdr *ip;
     const struct tcphdr *tcp;
     const u_char *payload;
     
     int size_eth = sizeof(struct ether_header);
     int size_ip = sizeof(struct iphdr);
     int size_tcp = sizeof(struct tcphdr);
     
     eth = (struct ether_header *)(packet);
     ip = (struct iphdr *)(packet + size_eth);
     tcp = (struct tcphdr *)(packet + size_eth + size_ip);
     payload = (u_char *)(packet + size_eth + size_ip + size_tcp);
     printf("got packet\n");
}


unsigned short csum (unsigned short *buf, int nwords){
  unsigned long sum;
  for (sum = 0; nwords > 0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

unsigned short tcp_csum(unsigned short *buf,int size){
    long sum;
    unsigned long odd;
    short answer;
    
    sum = 0;
    while(size > 1){
        sum+=*buf;
        size -=2;
    }
    
    if(size == 1){
        odd = 0;
        *((u_char*)&odd)=*(u_char*)buf;
        sum+=odd;
    }
    
    sum = (sum>>16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return(answer);
}

void ListInit(TList *l){
    l->act = NULL;
    l->first = NULL;
}

void InsertFirst(TList *l, int num){
    TElem *newElemPtr = (TElem *) malloc(sizeof(TElem));
    if(newElemPtr == NULL){
        fprintf(stderr, "Memory allocation error\n");
        exit(-1);
    }
    newElemPtr->port_num = num;
    newElemPtr->nextPtr = NULL;
    l->first = newElemPtr;
    l->act = newElemPtr;
}

void PostInsert(TList *l, int num){
    if(l->act != NULL){
        TElem *newElemPtr = (TElem *) malloc(sizeof(TElem));
        if(newElemPtr == NULL){
            fprintf(stderr, "Memory allocation error\n");
            exit(-1);
        }
        newElemPtr->port_num = num;
        newElemPtr->nextPtr = l->act->nextPtr;
        l->act->nextPtr = newElemPtr;
        l->act = newElemPtr;
    }
}


int main(int argc, char *argv[]){
    if(argc > 8 || argc == 7 || argc < 6){
        fprintf(stderr, "Incorrect number of arguments\n");
        exit(-1);
    }
    bool pu = false;
    bool pt = false;
    bool intface = false;
    bool addr = false;
    
    char* u_port;
    char* t_port;
    char* interface;
    char* address;
    
    int i=1;
    while(i < argc){
        if (strcmp(argv[i], "-pu") == 0){
            if ((strcmp(argv[i+1], "-pt") == 0) || (strcmp(argv[i+1], "-i") == 0)){
                fprintf(stderr, "Invalid arguments\n");
                exit(-1);
            }
            else{
                u_port = argv[i+1];
                
                bool dash_u = false;
                int coun = 0;
                for(int j=0; u_port[j]; j++){
                    if(u_port[j] == ','){
                        coun++;
                    }
                    else if(u_port[j] == '-'){
                        dash_u = true;
                        break;
                    }
                }
                
                TList *udp_ports = (TList *) malloc(sizeof(TList));
                ListInit(udp_ports);
                
                if(coun > 0){
                    
                    int cnt_u = 0;
                    char *ch = strtok(u_port, ",");
                    int number_u = atoi(ch);
                    InsertFirst(udp_ports, number_u);
                    
                    for(int j = 0; j<coun; j++){
                        ch = strtok(NULL, ",");
                        number_u = atoi(ch);
                        PostInsert(udp_ports, number_u);
                    }    
                }
                else if(dash_u == true){
                    char *pp = strtok(u_port, "-");
                    int n1 = atoi(pp);
                    InsertFirst(udp_ports, n1);
                    pp = strtok(NULL, "-");
                    int n2 = atoi(pp);
                    
                    
                    for(n1+=1; n1 <= n2; n1++){
                        PostInsert(udp_ports, n1);
                    }
                }
                else{
                    int n = atoi(u_port);
                    InsertFirst(udp_ports,n);
                }
                
                
                udp_ports->act = udp_ports->first;
                while(udp_ports->act->nextPtr != NULL){
                    printf("%d\n", udp_ports->act->port_num);
                    udp_ports->act = udp_ports->act->nextPtr;
                }
                printf("%d\n", udp_ports->act->port_num);
                
                
                pu = true;
                i += 2;
                continue;
            }
        }
        else if (strcmp(argv[i], "-pt") == 0) {
            if ((strcmp(argv[i+1], "-pu") == 0) || (strcmp(argv[i+1], "-i") == 0)){
                fprintf(stderr, "Invalid arguments\n");
                exit(-1);
            }
            else{
                t_port = argv[i+1];    
                bool dash = false;
                int count = 0;
                for(int j=0; t_port[j]; j++){
                    if(t_port[j] == ','){
                        count++;
                    }
                    else if(t_port[j] == '-'){
                        dash = true;
                        break;
                    }
                }
                
                TList *tcp_ports = (TList *) malloc(sizeof(TList));
                ListInit(tcp_ports);
                
                if(count > 0){
                    
                    int cnt = 0;
                    char *c = strtok(t_port, ",");
                    int number = atoi(c);
                    InsertFirst(tcp_ports, number);
                    
                    for(int j = 0; j<count; j++){
                        c = strtok(NULL, ",");
                        number = atoi(c);
                        PostInsert(tcp_ports, number);
                    }    
                }
                else if(dash == true){
                    char *p = strtok(t_port, "-");
                    int num1 = atoi(p);
                    InsertFirst(tcp_ports, num1);
                    p = strtok(NULL, "-");
                    int num2 = atoi(p);
                    
                    
                    for(num1+=1; num1 <= num2; num1++){
                        PostInsert(tcp_ports, num1);
                    }
                }
                else{
                    int num = atoi(t_port);
                    InsertFirst(tcp_ports,num);
                }
                
                
                tcp_ports->act = tcp_ports->first;
                while(tcp_ports->act->nextPtr != NULL){
                    printf("%d\n", tcp_ports->act->port_num);
                    tcp_ports->act = tcp_ports->act->nextPtr;
                }
                printf("%d\n", tcp_ports->act->port_num);
                
                pt = true;
                i +=2;
                
                continue;
            }
        }
        else if(strcmp(argv[i], "-i") == 0){
            if ((strcmp(argv[i+1], "-pt") == 0) || (strcmp(argv[i+1], "-pu") == 0)){
                fprintf(stderr, "Invalid arguments\n");
                exit(-1);
            }
            else {
                interface = argv[i+1];
                intface = true;
                i +=2;
                continue;
            }
        }
        else{
            address = argv[i];
            addr = true;
            i++;
            continue;
        }
    }
    
    if(pu == false || pt == false || addr == false){
        fprintf(stderr, "Missing argument(s)\n");
        exit(-1);
    }
    
    //NOT SURE!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    if (intface == false){
        interface = "wlp2s0";
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //ziska IP adresu ciela
    //hints.ai_family = AF_UNSPEC;
    //hints.ai_protocol = 0;
    struct addrinfo hints, *infoptr;
    hints.ai_socktype = 0;
    hints.ai_flags = AI_PASSIVE;
    
    int result = getaddrinfo(address, NULL, &hints, &infoptr);
    if(result != 0){
        fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(result));
        exit(1);
    }
    
    struct addrinfo *p;
    char host[256];
    
    for(p = infoptr; p != NULL; p = p->ai_next){
        int error = getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        if (error != 0){
             fprintf(stderr, "error in getnameinfo: %s\n", gai_strerror(error));
        }
        puts(host);
    }
    
    //freeaddrinfo(hints);
    //freeaddrinfo(p);
    freeaddrinfo(infoptr);
    
    
//////////////////////////////////////////////////////////////////////////////////////////
//MY DEVICE


    int socket_descriptor;
    struct ifreq ifr;
    
    socket_descriptor = socket(AF_INET, SOCK_DGRAM, 0);
    
    ifr.ifr_addr.sa_family = AF_INET;
    
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    
    ioctl(socket_descriptor, SIOCGIFADDR, &ifr);
    
    close(socket_descriptor);
    
    char* my_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    
     printf("%s\n", my_ip);
     
     
/////////////////////////////////////////////////////////////////////////////////
     
     char err_lookup[PCAP_ERRBUF_SIZE];
     char *dev = pcap_lookupdev(err_lookup);
     
     if(dev == NULL){
         fprintf(stderr, "Error in pcap_lookupdev: %s\n", err_lookup);
         exit(-1);
     } 
     else printf("pcap_lookupdev OK %s\n", dev);
     
     char err_pcap[PCAP_ERRBUF_SIZE];
     pcap_t* my_pcap = pcap_create(interface, err_pcap);
     if(my_pcap == NULL){
         fprintf(stderr, "error in pcap_create: %s\n",err_pcap );
     }
     else printf("pcap_create OK\n");
     
     int res = pcap_activate(my_pcap);
     if (res != 0){
         fprintf(stderr, "Something went wrong in pcap_activate\n");
     }
     else printf("pcap_activate OK\n");
     
     struct bpf_program fcode;
     
    int comp = pcap_compile(my_pcap, &fcode, "tcp", 1, 0);
    if (comp != 0){
        pcap_perror(my_pcap, "Error");
    }
    else printf("pcap_compile OK\n");
    int filter = pcap_setfilter(my_pcap, &fcode);
    if(filter != 0){
        pcap_perror(my_pcap, "error");
    }
    else printf("pcap_setfilter OK\n");
        
     //////////////////////////////////////////////////////////////////////////////////////////
     //Creates a raw socket with UDP protocol
     
     int sock_udp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
     
     if(sock_udp < 0){
         perror("socket() error");
         exit(-1);
     }
     else printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");
     
     
     //creates raw socket with TCP protocol
     int sock_tcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
     
     if(sock_tcp < 0){
         perror("socket() error");
         exit(-1);
     }
     else printf("socket() - Using SOCK_RAW socket and TCP protocol is OK.\n");
     
     int one = 1;
      const int *val = &one;
     
     
     //options for tcp socket
     int opt = setsockopt(sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
     if(opt < 0){
         fprintf(stderr, "setsockopt wrong\n");
     }
     else printf("setsockopt OK\n");



/////////////////IP AND TCP HEADER///////////////////////////////////////////////
     char buffer[4096]; //packet lenght
     struct ip *iph = (struct ip *) buffer;
     struct tcphdr *tcph = (struct tcphdr *)buffer + sizeof(struct ip);
     struct sockaddr_in sin;
     struct pseudoTCPpacket tcpPacket;
     char *pseudo_packet;
     char *data;
     
     sin.sin_family = AF_INET;
     sin.sin_port = htons(25);
     
     
     sin.sin_addr.s_addr = inet_addr(host); //zmeni IP na binary data
     memset(buffer, 0, 4096);
     data = (char *)(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr));
     strcpy(data, DATA);
     
     iph->ip_hl = 5;
     iph->ip_v = 4;
     iph->ip_tos = 0;
     iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + strlen(data);
     iph->ip_id = htons(54321);
     iph->ip_off = 0;
     iph->ip_ttl = 64;
     iph->ip_p = 6;
     iph->ip_sum = 0;
     iph->ip_src.s_addr = inet_addr(my_ip); 
     iph->ip_dst.s_addr = sin.sin_addr.s_addr;
     
     iph->ip_sum = tcp_csum((unsigned short*) buffer, iph->ip_len >> 1);
     
     
     tcph->th_sport = htons(80); //MODIFY !!!!!!!!!!!!!
     tcph->th_dport = htons(25);
     tcph->th_seq = htonl(1);
     //tcph->doff = 5;
     tcph->th_ack = 0;
     tcph->th_x2 = 0;
     //tcph->th_off = 5;
     tcph->th_flags = TH_SYN;
     tcph->th_win = htonl(32767); //maximum allowed windows size
     tcph->th_sum = 0;
     tcph->th_urp = 0;
     
     
    tcpPacket.srcAddr = inet_addr(my_ip);
    tcpPacket.dstAddr = inet_addr(host); 
    tcpPacket.zero = 0; 
    tcpPacket.protocol = IPPROTO_TCP; 
    tcpPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data));
    
    pseudo_packet = (char *)malloc((int) (sizeof(struct pseudoTCPpacket) + sizeof(struct tcphdr) + strlen(data)));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPpacket) + sizeof(struct tcphdr) + strlen(data));
    
    memcpy(pseudo_packet, (char *) &tcpPacket, sizeof(struct pseudoTCPpacket));
    
    tcph->th_sum = tcp_csum((unsigned short *)pseudo_packet, (int) (sizeof(struct pseudoTCPpacket) + sizeof(struct tcphdr) + strlen(data)));
    
    printf("TCP checksum: %d\n", tcph->th_sum);
    
    int bytes;
    if((bytes = sendto(sock_tcp, buffer, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin))) < 0){
         printf("Error in sendto\n");
    }
    else printf("sendto OK: %d bytes\n", bytes);


         /*UDP
         struct udphdr *udph = (struct udphdr *)buffer + sizeof(struct ip);
         udph->uh_sport =
         udph->uh_dport =
         udph->uh_ulen =
         udph->uh_sum =
         */
    
    
    int loop = pcap_loop(my_pcap, -1, packetHandler, NULL);
    /*struct pcap_pkthdr *h;
    if(pcap_next (my_pcap, h) == NULL){
        fprintf(stderr, "Error in pcap next\n");
    }
    else printf("pcap next OK\n");*/









}