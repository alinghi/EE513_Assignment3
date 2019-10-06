//---------------------------------------------------------------------------
//INCLUDE
//---------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>

#include <pcap.h>
#include <errno.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

//#define DEBUG

//---------------------------------------------------------------------------
//DEFINE
//---------------------------------------------------------------------------

#define KMAG  "\x1B[35m"
#define KRED  "\x1B[31m"
#define RESET "\x1B[0m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

//---------------------------------------------------------------------------
//STRUCT
//---------------------------------------------------------------------------

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14


/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp{
	u_short srcPort;
	u_short dstPort;
	u_short length;
	u_short checksum;
};

struct rule{

	bool valid;
	//protocol 1 tcp 2 udp 3 http
	int protocol;
	bool srcIPAny;
	bool dstIPAny;
	bool srcPortAny;
	bool dstPortAny;

	uint32_t srcIP;
	uint32_t dstIP;
	int srcCIDR;
	int dstCIDR;


	//1 - any 2 - colon 3 - comma 4- singlePort
	int srcPortType;
	int dstPortType;

	//if range srcPort[0]:LOWER BOUND srcPort[1]:UPPER BOUND
	int* srcPort;
	int numberSrcPort;
	//if range dstPort[0]:LOWER BOUND dstPort[1]:UPPER BOUND
	int* dstPort;
	int numberDstPort;

	//0 msg, 1 tos, 2 len, 3 offset, 4 seq, 5 ack, 6 flags, 7 http_request, 8 content
	//0 just print 1 IP 2 IP 3 IP 4 TCP 5 TCP 6 TCP 7 PAYLOAD 8 PAYLOAD
	bool check[9];
	//0 msg
	char message[500];
	//1 tos 6bit
	uint8_t tos;
	//2 len 16bit
	uint16_t len;
	//3 offset
	uint16_t offset;
	//4 seq
	uint32_t seqNumber;
	//5 ack
	uint32_t ackNumber;
	//6 flags
	//6-1 FIN 6-2 SYN 6-3 RST 6-4 PSH 6-5 ACK
	bool flags[5];
	//7 http_request
	//7-1 GET 7-2 POST 7-3 PUT 7-4 DELETE
	//7-5 HEAD 7-6 OPTIONS 7-7 TRACE 7-8 CONNECT
	char http[500];
	//8 content
	char content[500];
};


//Function Prototype 
void parser(char **argv);
int ruleCounter(char **argv);
void ruleMaker();
void displayRule(struct rule input,int rule_number);
void optionAdder(char* option, int rule_number);
int ip_parse(char *s, uint32_t *ip);
char *ip_tostring(uint32_t ip);
int digit(int number);
void packetAnalysis(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);


bool isIP(bool src,char *ip, int rule_number);
bool isPORT(bool src,int port, int rule_number);

//how many rules inside a file
int number_of_rules;

//raw string for each rule
char** raw_rule;
//check out number of options(count)
int* number_of_options;
//check out length of each rules
int* length_of_rules;
//parsed rule
struct rule* ruler;

int main(int argc, char **argv)
{
	parser(argv);
	ruleMaker();
	#ifdef DEBUG
	for(int i=0;i<number_of_rules;i++){
		displayRule(ruler[i],i);	
	}
	#endif

	//Network Part
	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	
	//USAGE
	// appname rule_file network_interface
	// appname rule_file
	if (argc == 3) {
		dev = argv[2];
	}
	else if (argc == 2) {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	else {
		printf("USAGE > Appname rule_file Network_interface\n");
		printf("                         OR\n");
		printf("USAGE > Appname rule_file\n");
		exit(EXIT_FAILURE);
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device Info: %s\n", dev);


	/* open capture device */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, 0, packetAnalysis, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");


	return 0;
}


void parser(char **argv){
	FILE *fp = NULL; 
    	fp = fopen(argv[1], "r" );
    	int counter=0;
    	int lines=1;
	char ch;
    	//check out IO error
    	if(!fp){
    		printf("File Open Error\n");
    		exit(1);
    	}

    	//calculate number of lines
	while(!feof(fp))
	{
	  ch = fgetc(fp);
	  if(ch == '\n')
	  {
	    lines++;
	  }
	}
	number_of_rules=lines;
	//Move to start point of file
	fseek( fp,  0, SEEK_SET);

	//Memory allocation for raw_rule
	raw_rule=(char**)malloc(number_of_rules * sizeof(char*));
	number_of_options=(int*)malloc(number_of_rules * sizeof(int));
	length_of_rules=(int*)malloc(number_of_rules * sizeof(int));
	ruler=(struct rule*)malloc(sizeof(struct rule)*number_of_rules);
	//Init
	memset(raw_rule,0,number_of_rules * sizeof(char*));
	memset(number_of_options,0,number_of_rules * sizeof(int*));
	memset(length_of_rules,0,number_of_rules * sizeof(int*));
	memset(ruler,0,number_of_rules * sizeof(struct rule));

	for(int i=0;i<number_of_rules;i++){
		raw_rule[i]=malloc(500*sizeof(char));
	}
	
	//0 msg, 1 tos, 2 len, 3 offset, 4 seq, 5 ack, 6 flags, 7 http_request, 8 content
	//bool check[9] init
	for(int i=0;i<number_of_rules;i++){
		for(int j=0;j<9;j++){
			(ruler[i]).check[j]=false;
		}
		for(int k=0;k<5;k++){
			(ruler[i]).flags[k]=false;
		}
	}

	while(!feof(fp)){
		fgets(raw_rule[counter++],500,fp);
	}

	fclose(fp);
}
/*----------------------------------------------------------------
Rule maker
- description : convert one rule line to structure
----------------------------------------------------------------*/
void ruleMaker()
{
	char * pch;
	char * ptr;
	char * pch2;

	int commaCounter;
	int temp;
	char IP[40];
	bool cidr;

	
	//1 iteration = 1 line of rule_file => 1 struct of rule
	for(int i=0;i<number_of_rules;i++){

		//check out alert
		pch = strtok (raw_rule[i]," ");

		//to prevent segmentation fault
		if(!pch){
			continue;
		}

		(ruler[i]).valid=false;
		if(strcmp(pch,"alert")==0){
			(ruler[i]).valid=true;
		}

		//protocol
		pch = strtok (NULL, " ");

		//to prevent segmentation fault
		if(!pch){
			continue;
		}

		if(strcmp(pch,"tcp")==0)
			(ruler[i]).protocol=1;
		else if(strcmp(pch,"udp")==0)
			(ruler[i]).protocol=2;
		else if(strcmp(pch,"http")==0)
			(ruler[i]).protocol=3;
		else
		{
			(ruler[i]).valid=false;
			(ruler[i]).protocol=0;
		}

//----------------------------------------------------------------
//SOURCE IP RULE
//----------------------------------------------------------------
		pch = strtok (NULL, " ");

		//to prevent segmentation fault
		if(!pch){
			continue;
		}

		//any
		cidr=false;
		temp=0;
		ruler[i].srcCIDR=32;
		memset(IP,0,40);
		if(strcmp("any",pch)==0){
			(ruler[i]).srcIPAny=true;
		}
		else{
			(ruler[i]).srcIPAny=false;
			//CIDR check
			for(int j=0;j<strlen(pch);j++)
			{
				//when CIDR happens
				if(*(pch+j)=='/'){
					temp=j;
					ruler[i].srcCIDR=atoi(pch+temp+1);
					cidr=true;
				}
			}
			//pick out IP
			if(cidr){
				strncpy(IP,pch,temp);
				ip_parse(IP, &(ruler[i].srcIP));
			}
			else{
				ip_parse(pch, &(ruler[i].srcIP));
			}
		}


//----------------------------------------------------------------
//SOURCE PORT RULE
//----------------------------------------------------------------
		pch = strtok (NULL, " ");

		//to prevent segmentation fault
		if(!pch){
			continue;
		}

		commaCounter=0;
		bool colon=false;
	//1 - any 2 - colon 3 - static 4 - single port
	//int srcPortType;
	//int dstPortType;

	//----------------------------------------------------------------
	//CASE1 - any
	//----------------------------------------------------------------
		//check out "any port"
		if(strcmp("any",pch)==0){
			(ruler[i]).srcPortAny=true;
			(ruler[i]).numberSrcPort=0;
			(ruler[i]).srcPortType=1;
		}
	//NOT any----------------------------------------------------

		//in case of "not any"
		else{
			(ruler[i]).srcPortAny=false;
			//check out comma or colon
			for(int i=0;i<strlen(pch);i++)
			{
				//when static port
				if(*(pch+i)==','){
					commaCounter++;
				}
				//when port range
				if(*(pch+i)==':'){
					colon=true;
				}
			}

	//----------------------------------------------------------------
	//CASE2 - colon
	//----------------------------------------------------------------
			//In case of colon
			if(colon==true){
				(ruler[i]).srcPortType=2;
				(ruler[i]).numberSrcPort=2;
				(ruler[i]).srcPort=malloc(sizeof(int)*2);
		//----------------------------------------------------------------
		//CASE2-1 - start with colon :port#
		//----------------------------------------------------------------
				if(*(pch)==':'){
					//printf("start colon\n");
					(ruler[i]).srcPort[0]=0;
					(ruler[i]).srcPort[1]=atoi(pch+1);
				}
		//----------------------------------------------------------------
		//CASE2-2 - finish with colon port#:
		//----------------------------------------------------------------
				else if(*(pch+strlen(pch)-1)==':'){
					//printf("end colon\n");
					(ruler[i]).srcPort[0]=atoi(pch);
					(ruler[i]).srcPort[1]=65535;
				}
		//----------------------------------------------------------------
		//CASE2-3 - port#:port#
		//----------------------------------------------------------------
				else{
					//printf("mid colon\n");
					(ruler[i]).srcPort[0]=atoi(pch);
					temp=atoi(pch);
					temp=digit(temp);
					(ruler[i]).srcPort[1]=atoi(pch+temp+1);
				}
			}

	//----------------------------------------------------------------
	//CASE3 - comma
	//----------------------------------------------------------------	
			else if(commaCounter>0 && colon==false){
				(ruler[i]).srcPortType=3;
				ptr=pch;
				(ruler[i]).numberSrcPort=commaCounter+1;
				(ruler[i]).srcPort=malloc(sizeof(int)*(commaCounter+1));
				for(int j=0;j<commaCounter+1;j++){
					(ruler[i]).srcPort[j]=atoi(ptr);
					temp=atoi(ptr);
					temp=digit(temp);
					ptr=ptr+temp+1;
				}
			}
	//----------------------------------------------------------------
	//CASE4 - single port
	//----------------------------------------------------------------
			else if(commaCounter==0 && colon==false){
				(ruler[i]).srcPortType=4;
				(ruler[i]).numberSrcPort=1;
				(ruler[i]).srcPort=malloc(sizeof(int));
				(ruler[i]).srcPort[0]=atoi(pch);
			}
			else{
				(ruler[i]).srcPortType=5;
				(ruler[i]).valid=false;
			}
		}
	//-----PORT end



		//->
		pch = strtok (NULL, " ");
		//to prevent segmentation fault
		if(!pch){
			continue;
		}

//----------------------------------------------------------------
//DEST IP RULE
//----------------------------------------------------------------
		pch = strtok (NULL, " ");
		//to prevent segmentation fault
		if(!pch){
			continue;
		}
		//any
		cidr=false;
		temp=0;
		ruler[i].dstCIDR=32;
		memset(IP,0,40);
		if(strcmp("any",pch)==0){
			(ruler[i]).dstIPAny=true;
		}
		else{
			(ruler[i]).dstIPAny=false;
			//CIDR check
			for(int j=0;j<strlen(pch);j++)
			{
				//when CIDR happens
				if(*(pch+j)=='/'){
					temp=j;
					ruler[i].dstCIDR=atoi(pch+temp+1);
					cidr=true;
				}
			}
			//pick out IP
			if(cidr){
				strncpy(IP,pch,temp);
				ip_parse(IP, &(ruler[i].dstIP));
			}
			else{
				ip_parse(pch, &(ruler[i].dstIP));
			}
		}

		//destPort
//----------------------------------------------------------------
//DEST PORT RULE
//----------------------------------------------------------------
		pch = strtok (NULL, " ");
		//to prevent segmentation fault
		if(!pch){
			continue;
		}
		commaCounter=0;
		colon=false;

	//----------------------------------------------------------------
	//CASE1 - any
	//----------------------------------------------------------------
		//check out "any port"
		if(strcmp("any",pch)==0){
			(ruler[i]).dstPortAny=true;
			(ruler[i]).numberDstPort=0;
			(ruler[i]).dstPortType=1;
		}

	//NOT any----------------------------------------------------
		//in case of "not any"
		else{
			(ruler[i]).dstPortAny=false;
			//check out comma or colon
			for(int i=0;i<strlen(pch);i++)
			{
				//when static port
				if(*(pch+i)==','){
					commaCounter++;
				}
				//when port range
				if(*(pch+i)==':'){
					colon=true;
				}
			}

	//----------------------------------------------------------------
	//CASE2 - colon
	//----------------------------------------------------------------
			//In case of colon
			if(colon==true){
				(ruler[i]).dstPortType=2;
				(ruler[i]).numberDstPort=2;
				(ruler[i]).dstPort=malloc(sizeof(int)*2);
		//----------------------------------------------------------------
		//CASE2-1 - start with colon :port#
		//----------------------------------------------------------------
				if(*(pch)==':'){
					//printf("start colon\n");
					(ruler[i]).dstPort[0]=0;
					(ruler[i]).dstPort[1]=atoi(pch+1);
				}
		//----------------------------------------------------------------
		//CASE2-2 - finish with colon port#:
		//----------------------------------------------------------------
				else if(*(pch+strlen(pch)-1)==':'){
					//printf("end colon\n");
					(ruler[i]).dstPort[0]=atoi(pch);
					(ruler[i]).dstPort[1]=65535;
				}
		//----------------------------------------------------------------
		//CASE2-3 - port#:port#
		//----------------------------------------------------------------
				else{
					//printf("mid colon\n");
					(ruler[i]).dstPort[0]=atoi(pch);
					temp=atoi(pch);
					temp=digit(temp);
					(ruler[i]).dstPort[1]=atoi(pch+temp+1);
				}
			}

	//----------------------------------------------------------------
	//CASE3 - comma
	//----------------------------------------------------------------	
			else if(commaCounter>0 && colon==false){
				(ruler[i]).dstPortType=3;
				ptr=pch;
				(ruler[i]).numberDstPort=commaCounter+1;
				(ruler[i]).dstPort=malloc(sizeof(int)*(commaCounter+1));
				for(int j=0;j<commaCounter+1;j++){
					(ruler[i]).dstPort[j]=atoi(ptr);
					temp=atoi(ptr);
					temp=digit(temp);
					ptr=ptr+temp+1;
				}
			}
	//----------------------------------------------------------------
	//CASE4 - single port
	//----------------------------------------------------------------
			else if(commaCounter==0 && colon==false){
				(ruler[i]).dstPortType=4;
				(ruler[i]).numberDstPort=1;
				(ruler[i]).dstPort=malloc(sizeof(int));
				(ruler[i]).dstPort[0]=atoi(pch);
			}
			else{
				(ruler[i]).dstPortType=5;
				(ruler[i]).valid=false;
			}
		}
	//-----PORT end
//----------------------------------------------------------------
//Parsing Option
//----------------------------------------------------------------
	#ifdef DEBUG
	printf("Option : %s",pch+strlen(pch)+1);
	#endif

	pch2=strtok(pch+strlen(pch)+1,"(;)");
	if(!pch2){
		continue;
	}
	//printf("Hey : %s\n",pch2);
	optionAdder(pch2,i);
		while(1){

			pch2=strtok(NULL,";)\n");
			if(!pch2)
				break;
			//printf("Hey : %s\n",pch2);
			optionAdder(pch2,i);
		}
	}
}


void optionAdder(char* option, int rule_number){
	int min=10000;
	int ptr=0;
	int pos=-1;
	char* flagP;
	if(strstr(option,"msg")){
		ptr=strstr(option,"msg")-option;
		if(min>ptr){
			min=ptr;
			pos=0;
		}
	}
	if(strstr(option,"tos")){
		ptr=strstr(option,"tos")-option;
		if(min>ptr){
			min=ptr;
			pos=1;
		}
	}
	if(strstr(option,"len")){
		ptr=strstr(option,"len")-option;
		if(min>ptr){
			min=ptr;
			pos=2;
		}
	}
	if(strstr(option,"offset")){
		ptr=strstr(option,"offset")-option;
		if(min>ptr){
			min=ptr;
			pos=3;
		}
	}
	if(strstr(option,"seq")){
		ptr=strstr(option,"seq")-option;
		if(min>ptr){
			min=ptr;
			pos=4;
		}
	}
	if(strstr(option,"ack")){
		ptr=strstr(option,"ack")-option;
		if(min>ptr){
			min=ptr;
			pos=5;
		}
	}
	if(strstr(option,"flags")){
		ptr=strstr(option,"flags")-option;
		if(min>ptr){
			min=ptr;
			pos=6;
		}
	}
	if(strstr(option,"http_request")){
		ptr=strstr(option,"http_request")-option;
		if(min>ptr){
			min=ptr;
			pos=7;
		}
	}
	if(strstr(option,"content")){
		ptr=strstr(option,"content")-option;
		if(min>ptr){
			min=ptr;
			pos=8;
		}
	}
	//#ifdef DEBUG
	//endif

	//To prevent segmentation fault
	if(pos==-1){
		if(option[0]==13){
			return;
		}
		printf("Some what invalid option %d\n", rule_number);
		printf("%d\n",option[0]);
		return;
	}

	#ifdef DEBUG
	printf(KRED  "%d %d\n",pos,rule_number);
	#endif
	
	(ruler[rule_number]).check[pos]=true;

	switch (pos) {
		//msg
		case 0 :
			strncpy((ruler[rule_number]).message,strchr(option,'"')+1,strlen(strchr(option,'"'))-2);
		break;
		
		//tos
		case 1 :
			ruler[rule_number].tos=atoi(strchr(option,':')+1);
		break;
		
		//len
		case 2 :
			ruler[rule_number].len=atoi(strchr(option,':')+1);
		break;
		
		//offset
		case 3 :
			ruler[rule_number].offset=atoi(strchr(option,':')+1);
		break;
		//seq
		case 4 :
			ruler[rule_number].seqNumber=atoi(strchr(option,':')+1);
		break;
		//ack
		case 5 :
			ruler[rule_number].ackNumber=atoi(strchr(option,':')+1);
		break;
		//flags
		case 6 :
			flagP=strchr(option,':')+1;
			//0 FIN 1 SYN 2 RST 3 PSH 4 ACK
			while(*flagP){
				if(*flagP=='F' || *flagP=='f'){
					//printf("FIN\n");
					ruler[rule_number].flags[0]=true;
				}
				if(*flagP=='S' || *flagP=='s'){
					//printf("SYN\n");
					ruler[rule_number].flags[1]=true;
				}
				if(*flagP=='R' || *flagP=='r'){
					//printf("RST\n");
					ruler[rule_number].flags[2]=true;
				}
				if(*flagP=='P' || *flagP=='p'){
					//printf("PSH\n");
					ruler[rule_number].flags[3]=true;
				}
				if(*flagP=='A' || *flagP=='a'){
					//printf("ACK\n");
					ruler[rule_number].flags[4]=true;
				}
				flagP++;
			}


		break;

		//http_request
		case 7 : 
			strncpy((ruler[rule_number]).http,strchr(option,'"')+1,strlen(strchr(option,'"'))-2);
		break;
		//contents
		case 8 :
			strncpy((ruler[rule_number]).content,strchr(option,'"')+1,strlen(strchr(option,'"'))-2);
		break;

		default : break;
	}

}

//THIS IS FOR DEBUGGING PURPOSE
void displayRule(struct rule input, int rule_number)
{
	printf(RESET "----------------------%3d rule-------------------\n",rule_number);
	printf("Valid : %d\n",input.valid);
	if(input.valid){
		printf("protocol : ");
		if(input.protocol==1)
			printf("TCP\n");
		else if(input.protocol==2)
			printf("UDP\n");
		else if(input.protocol==3)
			printf("HTTP\n");

		printf("==number src Port : %d==\n", input.numberSrcPort);
		if(input.srcPortType==1)
			printf("                 any src port\n");
		else if(input.srcPortType==2){
			printf("colon\n");
			printf("                %d ~ %d\n",input.srcPort[0],input.srcPort[1]);		
		}

		else if(input.srcPortType==3){
			printf("comma\n");
			printf("List of port\n");
			for(int i=0;i<input.numberSrcPort;i++){
				printf("                port : %d\n", input.srcPort[i]);
			}
		}
		else{
			printf("Single\n");
			printf("                port : %d\n",input.srcPort[0]);
		}

		printf("==number dst Port : %d==\n", input.numberDstPort);

		if(input.dstPortType==1)
			printf("                any dst port\n");
		else if(input.dstPortType==2){
			printf("colon\n");
			printf("                %d ~ %d\n",input.dstPort[0],input.dstPort[1]);		
		}

		else if(input.dstPortType==3){
			printf("comma\n");
			printf("List of port\n");
			for(int i=0;i<input.numberDstPort;i++){
				printf("                port : %d\n", input.dstPort[i]);
			}
		}
		else{
			printf("Single\n");
			printf("                port : %d\n",input.dstPort[0]);
		}
		if(input.srcIPAny){
			printf("SourceIP : any\n");	
		}
		else{
			printf("Source IP : %s\n",ip_tostring(input.srcIP));
		}
		printf("SRC CIDR %d\n",input.srcCIDR);
		if(input.dstIPAny){
			printf("DesIP : any\n");	
		}
		else{
			printf("Des IP : %s\n",ip_tostring(input.dstIP));
		}	
		printf("DST CIDR %d\n",input.dstCIDR);
		printf("print out option\n");

		//message
		if(input.check[0])
			printf("Message : \n%s\n",input.message);
		//tos
		if(input.check[1])
			printf("TOS : %u\n",input.tos);
		//len
		if(input.check[2])
			printf("LEN : %u\n",input.len);

		//offset
		if(input.check[3])
			printf("Offset : %u\n",input.offset);

		//seq
		if(input.check[4])
			printf("Seq number : %u\n",input.seqNumber);

		//ack
		if(input.check[5])
			printf("Ack number : %u\n",input.ackNumber);

		//flags
		if(input.check[6])
			printf("FIN %d, SYN %d, RST %d, PSH %d, ACK %d\n",input.flags[0],input.flags[1],input.flags[2],input.flags[3],input.flags[4]);

		//http
		if(input.check[7])
			printf("HTTP : %s\n", input.http);

		//content
		if(input.check[8])
			printf("CONTENT : %s\n",input.content);
		printf("-----------------------------------\n");		
	}

}





int ip_parse(char *s, uint32_t *ip)
{
    int ret;
    int b[4] = { 0, 0, 0, 0 };

    ret = sscanf(s, "%d.%d.%d.%d", b, b + 1, b + 2, b + 3);

    /* check we found all numbers */
    if (ret != 4) {
        return -1;
    }

    /* check 0 - 255 */
    for (int i = 0; i < 4; i++) {
        if (0 > b[i] || b[i] > 255) {
            return -1;
        }
    }

    /* reorder bytes into uint32 */
    *ip = ((uint32_t) b[0]) << 24
        | ((uint32_t) b[1]) << 16
        | ((uint32_t) b[2]) << 8
        | ((uint32_t) b[3]);

    return 0;
}

/* parse ip from uint32 to string */
char *ip_tostring(uint32_t ip)
{
    uint32_t a, b, c, d;
    char *s = malloc(15);

    a = (ip & 0xFF000000) >> 24;
    b = (ip & 0x00FF0000) >> 16;
    c = (ip & 0x0000FF00) >> 8;
    d = (ip & 0x000000FF);

    sprintf(s, "%d.%d.%d.%d", a, b, c, d);

    return s;
}

int digit(int number){
    int count = 0;
    if(number==0)
    	return 1;
    while(number != 0)
    {
        number /= 10;
        ++count;
    }

    return count;
}

void packetAnalysis(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//0 msg, 1 tos, 2 len, 3 offset, 4 seq, 5 ack, 6 flags, 7 http_request, 8 content
	//0 just print 1 IP 2 IP 3 IP 4 TCP 5 TCP 6 TCP 7 PAYLOAD 8 PAYLOAD
	//bool check[9];

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;
	const char *payload;                    /* Packet payload */

	//FOR COLORING
	//0 msg 1 tos 2 len 3 offset 4 seq 5 ack 6 flags 7 http_request 8 content
	bool mark[9];
	//check out address range
	//0 sourceIP 1 sourcePort 2 destinationIP 3 destinationPort
	bool addr[4];
	bool alert=false;
	bool flag=false;
	//1 TCP 2 UDP 3 OTHER
	int protocol;

	int size_ip;
	int size_tcp;
	int size_payload;
	int size_udp=8;
	printf(KGRN "\n----------Packet number %5d--------\n" RESET,count);
	count++;
	

	for(int z=0;z<number_of_rules;z++){
		//set boolean value after iteration
		
		alert=true;
		for(int k=0;k<9;k++){
			mark[k]=false;
		}
		for(int k=0;k<4;k++){
			addr[k]=false;
		}

		if((ruler[z]).valid){
			/* define ethernet header */
			ethernet = (struct sniff_ethernet*)(packet);
			
			/* define/compute ip header offset */
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip)*4;
			if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return;
			}
			addr[0]=isIP(true,inet_ntoa(ip->ip_src),z);
			addr[2]=isIP(false,inet_ntoa(ip->ip_dst),z);
			/* print source and destination IP addresses */

			#ifdef DEBUG2
			printf("       From: %s\n", inet_ntoa(ip->ip_src));
			printf("isSRC IP : %d \n", addr[0]=isIP(true,inet_ntoa(ip->ip_src),z));
			printf("         To: %s\n", inet_ntoa(ip->ip_dst));
			printf("isDST IP : %d \n", addr[2]=isIP(false,inet_ntoa(ip->ip_dst),z));
			printf("RULE SRC IP/CIDR : %s/%d\n",ip_tostring(ruler[z].srcIP),ruler[z].srcCIDR);
			#endif


			//IN CASE OF TCP
			if((ip->ip_p)==IPPROTO_TCP){
				//printf("Protocol:: TCP\n");
				/* define/compute tcp header offset */
				protocol=1;
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}
				addr[1]=isPORT(true,ntohs(tcp->th_sport),z);
				addr[3]=isPORT(false,ntohs(tcp->th_dport),z);
				#ifdef DEBUG2
				printf("   Src port: %d\n", ntohs(tcp->th_sport));
				printf(" isSRC %d\n", addr[1]=isPORT(true,ntohs(tcp->th_sport),z));
				printf("   Dst port: %d\n", ntohs(tcp->th_dport));
				printf(" isDST %d\n", addr[3]=isPORT(false,ntohs(tcp->th_dport),z));
				#endif
				/* define/compute tcp payload (segment) offset */
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
				
				/* compute tcp payload (segment) size */
				size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
				

			}
			else if((ip->ip_p)==IPPROTO_UDP){
				//printf("Protocol:: UDP\n");
				protocol=2;
				udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
				addr[1]=isPORT(true,ntohs(udp->srcPort),z);
				addr[3]=isPORT(false,ntohs(udp->dstPort),z);
				#ifdef DEBUG2
				printf("   Src port: %d\n", ntohs(udp->srcPort));
				printf(" isSRC %d\n", addr[1]=isPORT(true,ntohs(udp->srcPort),z));
				printf("   Dst port: %d\n", ntohs(udp->dstPort));
				printf(" isDST %d\n", addr[3]=isPORT(false,ntohs(udp->dstPort),z));
				#endif
				/* define/compute tcp payload (segment) offset */
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
				
				/* compute tcp payload (segment) size */
				size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
				
			}
			else{
				protocol=3;
				//printf("Protocol:: other or unknown\n");
				continue;
			}
			//ADDRESS TEST
			//printf("addr : %d %d %d %d\n",addr[0],addr[1],addr[2],addr[3]);
			if(addr[0]&&addr[1]&&addr[2]&&addr[3]){
				alert=true;
				if(ruler[z].protocol==1){
					if(protocol!=1){
						alert=false;
						continue;
					}
				}
				if(ruler[z].protocol==2){
					if(protocol!=2){
						alert=false;
						continue;
					}
				}

				//msg check - since it's necessary field
				if(!(ruler[z].check[0]))
					alert=false;

				//tos check
				if(ruler[z].check[1]){
					if(ip->ip_tos==(ruler[z]).tos){
						mark[1]=true;
					}
					else{
						//since its logical AND
						alert=false;
					}
				}
				//len check
				if(ruler[z].check[2]){
					if(IP_HL(ip)==(ruler[z]).len){
						mark[2]=true;
					}
					else{
						alert=false;
					}
				}
				//offset check
				if(ruler[z].check[3]){
					if(((ip->ip_off)&IP_OFFMASK)==(ruler[z]).offset){
						mark[3]=true;
					}
					else{
						alert=false;
					}
				}

				//seq check
				if(ruler[z].check[4]){

					//NOT TCP means no alert
					if(protocol!=1){
						alert=false;
						continue;
					}
					if((ruler[z]).seqNumber==tcp->th_seq){
						mark[4]=true;
					}
					else{
						alert=false;
					}
				}
				//ack check
				if(ruler[z].check[5]){

					//NOT TCP means no alert
					if(protocol!=1){
						alert=false;
						continue;
					}
					if((ruler[z]).ackNumber==tcp->th_ack){
						mark[5]=true;
					}
					else{
						alert=false;
					}
				}
				//flags check
				if(ruler[z].check[6] && protocol==1){
					//NOT TCP means no alert
					flag=true;

					//FIN
					if(ruler[z].flags[0]){
						
						if((TH_FIN&(tcp->th_flags))){
							
						}
						else
							flag=false;
					}

					//SYN
					if(ruler[z].flags[1]){
						if((TH_SYN&(tcp->th_flags))){
							
						}
						else
							flag=false;
					}

					//RST
					if(ruler[z].flags[2]){
						if((TH_RST&(tcp->th_flags))){
							
						}
						else
							flag=false;
					}

					//PSH
					if(ruler[z].flags[3]){
						if((TH_PUSH&(tcp->th_flags))){
							
						}
						else
							flag=false;
					}

					//ACK
					if(ruler[z].flags[4]){
						if((TH_ACK&(tcp->th_flags))){
							
						}
						else
							flag=false;
					}

					if(flag){
						mark[6]=true;
					}
					else{
						alert=false;
					}
				}
				//http_request check
				if(ruler[z].check[7]){
					char* temp;
					if(payload==NULL){
						alert=false;
						continue;
					}
					temp=strstr(payload,ruler[z].http);
					if(temp==NULL){
						alert=false;
					}
					else if(payload-temp==0){
						mark[7]=true;
					}
					else{
						alert=false;
					}
				}
				//content check
				if(ruler[z].check[8]){
					char* temp;
					if(payload==NULL){
						alert=false;
						continue;
					}
					temp=strstr(payload,ruler[z].content);
					if(temp==NULL){
						alert=false;
					}
					else{
						mark[8]=true;
					}
				}
				//printout when rule matched
				if(alert){
					printf(KYEL "**********RULE NUMBER %5d**********\n" RESET,z);
					printf("[IP HEADER]\n");

					printf("* Version : %d\n",IP_V(ip));
					//1
					if(mark[1])
						printf(KRED "* TOS : 0x%x\n" RESET,ip->ip_tos);
					else
						printf("* TOS : 0x%x\n",ip->ip_tos);
					//2
					if(mark[2]){
						printf(KRED "* Header Length : %4d Bytes\n" RESET,IP_HL(ip)*4);
						printf(KRED "* Header Length : %4d Exact Value\n" RESET,IP_HL(ip));
					}
					else{
						printf("* Header Length : %4d Bytes\n",IP_HL(ip)*4);
						printf("* Header Length : %4d Exact Value\n",IP_HL(ip));
					}
					//3
					if(mark[3])
						printf(KRED "* Fragment OFFSET : %d\n" RESET,(ip->ip_off)&IP_OFFMASK);
					else
						printf("* Fragment OFFSET : %d\n",(ip->ip_off)&IP_OFFMASK);
					printf("-----------------------------\n\n");

					if(protocol==1){
						printf("PROTOCOL : TCP\n");
						printf("[TCP HEADER]\n");
						printf("* Src port: %d\n", ntohs(tcp->th_sport));
						printf("* Dst port: %d\n", ntohs(tcp->th_dport));
						if(mark[4]){
							printf(KRED "* Sequence Number %u\n" RESET,(tcp->th_seq));	
						}
						else{
							printf("* Sequence Number %u\n",(tcp->th_seq));
						}
						if(mark[5]){
							printf(KRED "* Ack Number %u\n" RESET,(tcp->th_ack));	
						}
						else{
							printf("* Ack Number %u\n",(tcp->th_ack));
						}
						if(mark[6]){
							printf(KRED "FLAG\n" RESET);
							printf(KRED "FIN %d, SYN %d, RST %d, PSH %d, ACK %d\n" RESET,ruler[z].flags[0],ruler[z].flags[1],ruler[z].flags[2],ruler[z].flags[3],ruler[z].flags[4]);
						}
						else{
							printf("FLAG\n");
						}
						
					}
					else if(protocol==2){
						printf("PROTOCOL : UDP\n");
						printf("[UDP HEADER]\n");
						printf("   Src port: %d\n", ntohs(udp->srcPort));
						printf("   Dst port: %d\n", ntohs(udp->dstPort));
					}
					else{
						printf("PROTOCOL : UNKNOWN or OTHER\n");
					}

					if (size_payload > 0) {
						printf("-----------------------------\n\n");
						if(mark[7]){
							printf(KRED "HTTP REQUEST: %s\n" RESET, ruler[z].http);
						}
						if(mark[8]){
							printf(KRED "CONTENT: %s\n" RESET, ruler[z].content);
						}
						printf("\n   Payload (%d bytes):\n", size_payload);
						print_payload(payload, size_payload);
					}
					printf("-----------------------------\n\n");
					printf(KMAG "MESSAGE : %s\n\n" RESET,ruler[z].message);

				}

			}

	
		}

		
	}

	return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{


	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

bool isPORT(bool src, int port, int rule_number)
{
	//in case of source port check
	if(src){
		//check port type
		switch((ruler[rule_number]).srcPortType){
			//any
			case 1:
				return true;
			//range
			case 2:
				if(ruler[rule_number].srcPort[0]<=port && ruler[rule_number].srcPort[1]>=port )
					return true;
				else
					return false;
			//comma -static port
			case 3:
				for(int x=0;x<ruler[rule_number].numberSrcPort;x++){
					if(ruler[rule_number].srcPort[x]==port)
						return true;
				}
				return false;
			//single port
			case 4:
				if(ruler[rule_number].srcPort[0]==port)
					return true;
				else
					return false;
			default:
				return false;
		}
	}
	//in case of destination port check
	else{
		//check port type
		switch((ruler[rule_number]).dstPortType){
			//any
			case 1:
				return true;
			//range
			case 2:
				if(ruler[rule_number].dstPort[0]<=port && ruler[rule_number].dstPort[1]>=port )
					return true;
				else
					return false;
			//comma -static port
			case 3:
				for(int x=0;x<ruler[rule_number].numberDstPort;x++){
					if(ruler[rule_number].dstPort[x]==port)
						return true;
				}
				return false;
			//single port
			case 4:
				if(ruler[rule_number].dstPort[0]==port)
					return true;
				else
					return false;
			default:
				return false;
		}
	}
}

bool isIP(bool src, char *ip, int rule_number)
{
	char *orig;
	int cidr;
	int a[4]={0,0,0,0};
	int b[4]={0,0,0,0};
	bool c[4]={false,false,false,false};

	if(src)
	{
		if(ruler[rule_number].srcIPAny){
			return true;
		}
		orig=ip_tostring(ruler[rule_number].srcIP);
		cidr=ruler[rule_number].srcCIDR;
		sscanf(ip, "%d.%d.%d.%d", a, a + 1, a + 2, a + 3);
		//printf("a : %d %d %d %d\n", a[0],a[1],a[2],a[3]);
		sscanf(orig, "%d.%d.%d.%d", b, b + 1, b + 2, b + 3);
		//printf("b : %d %d %d %d\n", b[0],b[1],b[2],b[3]);
		for(int i=0;i<4;i++){
			if(a[i]==b[i])
				c[i]=true;
			else
				c[i]=false;
		}
		//printf("c : %d %d %d %d\n", c[0],c[1],c[2],c[3]);
		if(cidr==8){
			if(c[0])
				return true;
			else
				return false;
		}

		else if(cidr==16){
			if(c[0]&&c[1])
				return true;
			else
				return false;
		}

		else if(cidr==24){
			if(c[0]&&c[1]&&c[2])
				return true;
			else
				return false;
		}
		else if(cidr==32){
			if(c[0]&&c[1]&&c[2]&&c[3])
				return true;
			else
				return false;
		}
		else{
			return false;
		}

	}

	else
	{
		if(ruler[rule_number].dstIPAny){
			return true;
		}
		orig=ip_tostring(ruler[rule_number].dstIP);
		cidr=ruler[rule_number].dstCIDR;
		sscanf(ip, "%d.%d.%d.%d", a, a + 1, a + 2, a + 3);
		//printf("a : %d %d %d %d\n", a[0],a[1],a[2],a[3]);
		sscanf(orig, "%d.%d.%d.%d", b, b + 1, b + 2, b + 3);
		//printf("b : %d %d %d %d\n", b[0],b[1],b[2],b[3]);
		for(int i=0;i<4;i++){
			if(a[i]==b[i])
				c[i]=true;
			else
				c[i]=false;
		}
		//printf("c : %d %d %d %d\n", c[0],c[1],c[2],c[3]);
		if(cidr==8){
			if(c[0])
				return true;
			else
				return false;
		}

		else if(cidr==16){
			if(c[0]&&c[1])
				return true;
			else
				return false;
		}

		else if(cidr==24){
			if(c[0]&&c[1]&&c[2])
				return true;
			else
				return false;
		}
		else if(cidr==32){
			if(c[0]&c[1]&c[2]&c[3])
				return true;
			else
				return false;
		}
		else{
			return false;
		}

	}
}