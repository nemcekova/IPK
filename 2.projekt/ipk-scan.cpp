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
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>
#define __USE_BSD
#define __FAVOR_BSD


int main(int argc, char *argv[]){
    if(argc > 8 || argc == 7 || argc < 6){
        fprintf(stderr, "Incorrect number of arguments\n");
        exit(-1);
    }
    bool pu = false;
    bool pt = false;
    bool intface = false;
    bool addr = false;
    
    char* udp_port;
    char* tcp_port;
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
                udp_port = argv[i+1];
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
                tcp_port = argv[i+1];
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

    //ZMENIT PREMENNEEEEEEEEEEEEEE a zistit co to vlastne robi
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
     
     sin.sin_family = AF_INET;
     sin.sin_port = htons(25);
     
     
     sin.sin_addr.s_addr = inet_addr(my_ip); //zmeni IP na binary data
     memset(buffer, 0, 4096);
     
     iph->ip_hl = 5;
     iph->ip_v = 4;
     iph->ip_tos = 0;
     iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
     iph->ip_id = htons(54321);
     iph->ip_off = 0;
     iph->ip_ttl = 64;
     iph->ip_p = 6;
     iph->ip_sum = 0;
     iph->ip_src.s_addr = inet_addr("1.2.3.4"); //MODIFY !!!!!!!!!!!!!!!
     iph->ip_dst.s_addr = sin.sin_addr.s_addr;
     











}