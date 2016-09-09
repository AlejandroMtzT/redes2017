#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "pcap.h"

int dispositivos(){
    char *dev = NULL;
    char ebuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char filter_exp[]= "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    int num_packets;
    pcap_if_t* deviceList;
    if (pcap_findalldevs(&deviceList,ebuf)){
        printf("No se puede accesar a ningun dispositivo %s\n", ebuf);
        exit(1);
    }else{
        printf("Dispositivos: \n");
    }
    int i = 1;
    while(deviceList->next != NULL ) {
        printf("%d.-%s \n", i, (deviceList->name));
        deviceList = deviceList->next;
        i++;
    } 
    printf("Selecciona el dispositivo: \n");
    char *word = (char *) malloc(sizeof(char)*10);
    scanf("%s",word);
    dev = word;

    if(dev == NULL){
        printf("Dispositivo invalido \n");
        return -1;
    }

    if(pcap_lookupnet(dev, &net, &mask, ebuf)==-1){
        net= 0;
        mask = 0;
    }
    printf("Capturarndo: %s\n\n", dev);

    handle = pcap_open_live(dev, SNAP_LEN,1,1000,ebuf);
    if(handle == NULL){
        return -1;  
    }

    if(pcap_compile(handle, &fp,filter_exp,0,net)==-1){
        return -1;
    }

    if(pcap_setfilter(handle, &fp) == -1){
        return -1;
    }
    pcap_loop(handle, num_packets, got_packet, NULL);
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\n");
    return 0;
}

int capturar(){
    printf("\n");
    char ebuf[PCAP_ERRBUF_SIZE];
    printf("Seleccionar archivo: \n");
    char dev[256];
    fgets(dev, sizeof dev, stdin);

    char *as;
    if ((as = strchr(dev, '\n')) != NULL){
        *as = '\0';
    }
    if(dev == NULL){
        printf("Dispositivo invalido \n");
        return -1;
    }

    printf("ANalizando archivo: %s\n", dev);
    pcap_t *captura;
    captura = pcap_open_offline(dev, ebuf);
    if(captura == NULL) {
        printf("Error en captura %s\n", ebuf);
        return -1;
    }
    leer(captura, dev);
    printf("\n");
}

int leer(pcap_t* captura, char* dev){
    pcap_loop(captura,-1,got_packet, NULL);
    pcap_close(captura);
    return 1;
}

void translate(char *string){
    printf("\n");
    const u_char *ch;
    ch = string;

    while(isprint(*ch)){
        printf("%c", *ch);
        ch++;
    }
    printf("\n");
    printf("\n");
}

void headerF(const char *buffer){
    printf("\n");
    printf("Header: \n");
    printf("Version: %c%c%c%c%c%c%c%c \n",buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],buffer[5],buffer[6],buffer[7]);
    printf("%c \n",buffer[8]);
    printf("Status: %c%c%c \n", buffer[9], buffer[10], buffer[11]);

    char *str_connection = strstr(buffer, "Connection:");
    if (str_connection == NULL)
        printf("Connection: CAmpo no definido \n");
    else
        translate(str_connection);

    char *str_date = strstr(buffer, "Date: ");
    if (str_date == NULL)
        printf("Date: Campo no definido \n");
    else
        translate(str_date);

    char *str_server = strstr(buffer, "Server: ");
    if (str_server == NULL)
        printf("Server: Campo no definido \n");
    else
        translate(str_server);

    char *str_last_modified = strstr(buffer, "Last-Modified: ");
    if (str_last_modified == NULL)
        printf("Last-Modified: Campo no definido \n");
    else
        translate(str_last_modified);

    char *str_content_length = strstr(buffer, "Content-Length: ");
    if (str_content_length == NULL)
        printf("Content-Length: Campo no definido \n");
    else
        translate(str_content_length);

    char *str_content_type = strstr(buffer, "Content-Type: ");
    if (str_content_type == NULL)
        printf("Content-Type: CAMpo no definido \n");
    else
        translate(str_content_type);

    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	static int count = 1;                   /* packet counter */
 	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
 	const struct sniff_ip *ip;              /* The IP header */
 	const struct sniff_tcp *tcp;            /* The TCP header */
 	const char *payload;                    /* Packet payload */
 
	int size_ip;
 	int size_tcp;
 	int size_payload;
 

	printf("\nPacket number %d:\n", count);
	count++;

	ethernet = (struct sniff_ethernet*)(packet);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
  		printf("   * Invalid IP header length: %u bytes\n", size_ip);
 	return;
 	}
 	printf("       From: %s\n", inet_ntoa(ip->ip_src));
 	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
 	switch(ip->ip_p) {
  		case IPPROTO_TCP:
   			printf("   Protocol: TCP\n");
   		break;
  		case IPPROTO_UDP:
   			printf("   Protocol: UDP\n");
   		return;
  		case IPPROTO_ICMP:
   			printf("   Protocol: ICMP\n");
   		return;
  		case IPPROTO_IP:
   			printf("   Protocol: IP\n");
   		return;
  		default:
   			printf("   Protocol: unknown\n");
   		return;
 	}
  
 	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
 	size_tcp = TH_OFF(tcp)*4;
 	if (size_tcp < 20) {
  		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
  	return;
 	}
  
 	printf("   Src port: %d\n", ntohs(tcp->th_sport));
 	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
  
 	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
  
 	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
  
 	if (size_payload > 0) {
  		printf("   Payload (%d bytes):\n", size_payload);
  		if(strstr(payload, "HTTP")){
  			headerF(payload);
  		}
 	}
 
	return;
}

int main () {
    int i;
    char c;
    printf("\n");
    printf("Seleccionar accion: \n");
    do{
        printf("1.-Escuchar indefinidamente \n2.-Lectura de captura de archivo seleccionado \n");
    }while(((scanf("%d%c", &i, &c)!=2 || c!='\n')) || i<1 || i>2);
    if (i == 1){
        dispositivos();
    }else{
        capturar();
    }
    return 0;
}
