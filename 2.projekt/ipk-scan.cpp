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
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "header.h"
#define __USE_BSD
#define __FAVOR_BSD
#define DATA "datastring"
#define ETHER_ADDR_LEN 
pcap_t* my_pcap;


struct pseudoPacket{
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t leng;
};


void packetHandler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet ){
    
     const struct ether_header *eth;
     const struct iphdr *ip;
     const struct tcphdr *tcp;
     const struct udphdr *udp;
     const u_char *payload;
     char* typ;
     
     int size_eth = sizeof(struct ether_header);
     int size_ip = sizeof(struct iphdr);
     int size_tcp = sizeof(struct tcphdr);
     int size_udp = sizeof(struct udphdr);
     
     eth = (struct ether_header *)(packet);
     ip = (struct iphdr *)(packet + size_eth);
     tcp = (struct tcphdr *)(packet + size_eth + size_ip);
     udp = (struct udphdr *)(packet + size_eth + size_ip);
     payload = (u_char *)(packet + size_eth + size_ip + size_tcp);
     
     if( ip->protocol == IPPROTO_TCP){
         typ = "tcp";
     }
     else if(ip->protocol == IPPROTO_UDP){
         typ = "udp";
     }
     
     if(tcp->syn == 1 && tcp->ack == 0){
     }
     else if(tcp->ack == 1 && tcp->syn == 1){
         printf("%d/%s open\n", ntohs(tcp->th_sport), typ);
         pcap_breakloop(my_pcap);
         return;
     }
     else if(tcp->rst == 1 && tcp->ack == 1){
         printf("%d/%s closed\n", ntohs(tcp->th_sport), typ);
         pcap_breakloop(my_pcap);
         return;
     }
     
    /* if(udp->syn == 1 && udp->ack == 0){
     }
     else if(udp->ack == 1 && udp->syn == 1){
         printf("%d/%s open\n", ntohs(tcp->th_sport), typ);
         pcap_breakloop(my_pcap);
         return;
     }
     else if(udp->rst == 1 && udp->ack == 1){
         printf("%d/%s closed\n", ntohs(tcp->th_sport), typ);
         pcap_breakloop(my_pcap);
         return;
     }*/
}


unsigned short tcp_csum(unsigned short *buf,int size){
    long sum;
    unsigned long odd;
    short answer;
    
    sum = 0;
    while(size > 1){
        sum+=*buf++;
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

pcap_t *new_pcap_funcion(char* interface){
    char err_lookup[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(err_lookup);

    if(dev == NULL){
        fprintf(stderr, "Error in pcap_lookupdev: %s\n", err_lookup);
        exit(-1);
    } 
    //     else printf("pcap_lookupdev OK %s\n", dev);

    char err_pcap[PCAP_ERRBUF_SIZE];
    //my_pcap = pcap_create(interface, err_pcap);
    my_pcap = pcap_open_live(interface, BUFSIZ, 0, 150, err_pcap);
    if(my_pcap == NULL){
        fprintf(stderr, "error in pcap_create: %s\n",err_pcap );
        exit(-1);
    }
    // else printf("pcap_create OK\n");

    /* int res = pcap_activate(my_pcap);
    if (res != 0){
        fprintf(stderr, "Something went wrong in pcap_activate\n");
        exit(-1);
    }*/
    //else printf("pcap_activate OK\n");

    struct bpf_program fcode;

    int comp = pcap_compile(my_pcap, &fcode, "tcp", 1, 0);
    if (comp != 0){
       pcap_perror(my_pcap, "Error");
       exit(-1);
    }
    //else printf("pcap_compile OK\n");
    int filter = pcap_setfilter(my_pcap, &fcode);
    if(filter != 0){
       pcap_perror(my_pcap, "error");
       exit(-1);
    }
    //else printf("pcap_setfilter OK\n");
    return(my_pcap);
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
    
    TList *tcp_ports = (TList *) malloc(sizeof(TList));
    ListInit(tcp_ports);
    
    TList *udp_ports = (TList *) malloc(sizeof(TList));
    ListInit(udp_ports);
    
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
                
                
                /*udp_ports->act = udp_ports->first;
                while(udp_ports->act->nextPtr != NULL){
                    printf("%d\n", udp_ports->act->port_num);
                    udp_ports->act = udp_ports->act->nextPtr;
                }
                printf("%d\n", udp_ports->act->port_num);*/
                
                
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
                
                
                /*tcp_ports->act = tcp_ports->first;
                while(tcp_ports->act->nextPtr != NULL){
                    printf("%d\n", tcp_ports->act->port_num);
                    tcp_ports->act = tcp_ports->act->nextPtr;
                }
                //printf("%d\n", tcp_ports->act->port_num);*/
                
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
        struct ifaddrs *addrs,*tmp;

        getifaddrs(&addrs);
        tmp = addrs;

        while (tmp){
            if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_INET){
                
                printf("%d\n", tmp->ifa_addr);
            
            }
            tmp = tmp->ifa_next;
    }
    freeifaddrs(addrs);
    exit(0);
}
//////////////////////////////////////////////////////////////////////////////////////////
    //ziska IP adresu ciela

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
        //puts(host);
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
    
    // printf("%s\n", my_ip);
     
     
/////////////////////////////////////////////////////////////////////////////////
     
     my_pcap = new_pcap_funcion(interface);
        
     //////////////////////////////////////////////////////////////////////////////////////////
     //Creates a raw socket with UDP protocol
     
     int sock_udp = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
     
     if(sock_udp < 0){
         perror("socket() error");
         exit(-1);
     }
    // else printf("socket() - Using SOCK_RAW socket and UDP protocol is OK.\n");
     
     
     //creates raw socket with TCP protocol
     int sock_tcp = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
     
     if(sock_tcp < 0){
         perror("socket() error");
         exit(-1);
     }
//     else printf("socket() - Using SOCK_RAW socket and TCP protocol is OK.\n");
     
     int one = 1;
      const int *val = &one;
     
     
     //options for tcp socket
     int opt = setsockopt(sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));
     if(opt < 0){
         fprintf(stderr, "setsockopt wrong\n");
     }
    // else printf("setsockopt OK\n");

int looper = 1;
tcp_ports->act = tcp_ports->first;
while(tcp_ports->act->nextPtr != NULL){
    looper++;
    tcp_ports->act = tcp_ports->act->nextPtr;
}

tcp_ports->act = tcp_ports->first;
for(int z=0; z<looper; z++){
/////////////////IP AND TCP HEADER///////////////////////////////////////////////
     char buffer[4096]; //packet lenght
     memset(buffer, 0, sizeof(buffer));
     struct iphdr *iph = (struct iphdr *)( buffer);
     struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct ip));
     struct sockaddr_in sin;
     struct pseudoPacket tcpPacket;
     struct pseudoPacket udpPacket;
     char *pseudo_packet;
     char *data;
     
     sin.sin_family = AF_INET;
     sin.sin_port = htons(25);
     
     
     sin.sin_addr.s_addr = inet_addr(host); //zmeni IP na binary data
     data = (char *)(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr));
     strcpy(data, DATA);
     
    
     iph->ihl = 5; //5 x 32-bit words in the header
     iph->version = 4; // ipv4
     iph->tos = 0;// //tos = [0:5] DSCP + [5:7] Not used, low delay
     iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data); //total lenght of packet. len(data) = 0
     iph->id = htons(54321); // 0x00; //16 bit id
     iph->frag_off = 0x00; //16 bit field = [0:2] flags + [3:15] offset = 0x0
     iph->ttl = 0xFF; //16 bit time to live (or maximal number of hops)
     iph->protocol = IPPROTO_TCP; //TCP protocol
     iph->check = 0; //16 bit checksum of IP header. Can't calculate at this point
     iph->saddr = inet_addr(my_ip); //32 bit format of source address
     iph->daddr = inet_addr(host); //32 bit format of source address
     
     iph->check = tcp_csum((unsigned short*) buffer, iph->tot_len );
     
     

     
      tcph->source = htons(25); //16 bit in nbp format of source port
      tcph->dest = htons(tcp_ports->act->port_num); //16 bit in nbp format of destination port
      tcph->seq = 0x0; //32 bit sequence number, initially set to zero
      tcph->ack_seq = 0x0; //32 bit ack sequence number, depends whether ACK is set or not
      tcph->doff = 5; //4 bits: 5 x 32-bit words on tcp header
      tcph->res1 = 0; //4 bits: Not used
      tcph->urg = 0; //Urgent flag
      tcph->ack = 0; //Acknownledge
      tcph->psh = 0; //Push data immediately
      tcph->rst = 0; //RST flag
      tcph->syn = 1; //SYN flag
      tcph->fin = 0; //Terminates the connection
      tcph->window = htons(155);//0xFFFF; //16 bit max number of databytes 
      tcph->check = 0; //16 bit check sum. Can't calculate at this point
      tcph->urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set

      
     
     
    tcpPacket.srcAddr = inet_addr(my_ip);
    tcpPacket.dstAddr = inet_addr(host); 
    tcpPacket.zero = 0; 
    tcpPacket.protocol = IPPROTO_TCP; 
    tcpPacket.leng = htons(sizeof(struct tcphdr) + strlen(data));
    
    int psize = (sizeof(struct pseudoPacket) + sizeof(struct tcphdr) + strlen(data));
    pseudo_packet = (char *)malloc(psize);
    
    memcpy(pseudo_packet, (char *) &tcpPacket, sizeof(struct pseudoPacket));
    memcpy(pseudo_packet + sizeof(struct pseudoPacket), tcph, sizeof(struct tcphdr) + strlen(data));
    
    
    tcph->check = tcp_csum((unsigned short *)pseudo_packet, (int) (sizeof(struct pseudoPacket) + sizeof(struct tcphdr) + strlen(data)));
    
    //printf("TCP checksum: %d\n", tcph->check);
    
    int bytes;
    if((bytes = sendto(sock_tcp, buffer, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin))) < 0){
         perror("send to error: ");
         exit(-1);
    }
    //else printf("sendto OK: %d bytes\n", bytes);


         
    
    int loop = pcap_dispatch(my_pcap, -1, packetHandler, NULL);
    if(loop == 1){
         my_pcap = new_pcap_funcion(interface);
        int loop2 = pcap_dispatch(my_pcap, -1, packetHandler, NULL);
        if(loop2 == 0){
            char* type;
            if( iph->protocol == IPPROTO_TCP){
                type = "tcp";
            }
            else if(iph->protocol == IPPROTO_UDP){
                type = "udp";
            }
            printf("%d/%s filtered\n", tcp_ports->act->port_num, type);
        }
    }
    tcp_ports->act = tcp_ports->act->nextPtr;
     my_pcap = new_pcap_funcion(interface);
}


//###############################################################################################################
//###############################################################################################################

int loop0 = 1;
udp_ports->act = udp_ports->first;
while(udp_ports->act->nextPtr != NULL){
    loop0++;
    udp_ports->act = udp_ports->act->nextPtr;
}
//printf("%d\n", loop0);
udp_ports->act = udp_ports->first;
for(int z=0; z<loop0; z++){
/////////////////IP AND TCP HEADER///////////////////////////////////////////////
     char buffer[1024]; //packet lenght
     memset(buffer, 0, sizeof(buffer));
     struct iphdr *iph = (struct iphdr *)( buffer);
     struct udphdr *udph = (struct udphdr *)(buffer + sizeof(struct ip));
     struct sockaddr_in sin;
     struct pseudoPacket udpPacket;
     char *pseudogram;
     char *datas;
     
     sin.sin_family = AF_INET;
     sin.sin_port = htons(25);
     
     
     sin.sin_addr.s_addr = inet_addr(host);
     datas = (char *)(buffer + sizeof(struct iphdr) + sizeof(struct tcphdr));
     strcpy(datas, DATA);
     
    
     iph->ihl = 5; //5 x 32-bit words in the header
     iph->version = 4; // ipv4
     iph->tos = 0;// //tos = [0:5] DSCP + [5:7] Not used, low delay
     iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(datas); //total lenght of packet. len(data) = 0
     iph->id = 1; // 0x00; //16 bit id
     iph->frag_off = 0x00; //16 bit field = [0:2] flags + [3:15] offset = 0x0
     iph->ttl = 0xFF; //16 bit time to live (or maximal number of hops)
     iph->protocol = IPPROTO_TCP; //TCP protocol
     iph->check = 0; //16 bit checksum of IP header. Can't calculate at this point
     iph->saddr = inet_addr(my_ip); //32 bit format of source address
     iph->daddr = inet_addr(host); //32 bit format of source address
     
     iph->check = tcp_csum((unsigned short*) buffer, iph->tot_len );
     printf("%d\n", iph->tot_len);

     /*UDP*/
     udph->uh_sport = htons(25);
     udph->uh_dport = htons(udp_ports->act->port_num);
     udph->uh_ulen = htons(8 + sizeof(datas));
     udph->uh_sum = 0;
     
     udpPacket.srcAddr = inet_addr(my_ip);
     udpPacket.dstAddr = inet_addr(host);
     udpPacket.zero = 0;
     udpPacket.protocol = IPPROTO_UDP;
     udpPacket.leng = htons(sizeof(struct udphdr) + strlen(datas));
     printf("%d\n", udpPacket.leng);
     
     int psize = (sizeof(struct pseudoPacket) + sizeof(struct udphdr) + strlen(datas));
	 pseudogram = (char *)malloc(psize);
	
	 memcpy(pseudogram , (char*) &udpPacket , sizeof(struct pseudoPacket));
	 memcpy(pseudogram + sizeof(struct pseudoPacket) , udph , sizeof(struct udphdr) + strlen(datas));
	
	 udph->uh_sum = tcp_csum( (unsigned short*) pseudogram , psize);
     
     
     int ret;
     if((ret = sendto(sock_udp, buffer, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin))) < 0){
          perror("send to error: ");
          exit(-1);
     }


     my_pcap = new_pcap_funcion(interface);
     int loop1 = pcap_dispatch(my_pcap, -1, packetHandler, NULL);
     if(loop1 == 1){
          my_pcap = new_pcap_funcion(interface);
         int loop2 = pcap_dispatch(my_pcap, -1, packetHandler, NULL);
         if(loop2 == 0){
             char* type;
             if( iph->protocol == IPPROTO_TCP){
                 type = "tcp";
             }
             else if(iph->protocol == IPPROTO_UDP){
                 type = "udp";
             }
             printf("%d/%s filtered\n", udp_ports->act->port_num, type);
         }
     }
     udp_ports->act = udp_ports->act->nextPtr;
      my_pcap = new_pcap_funcion(interface);
}

return 0;
}