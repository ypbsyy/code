#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <string.h> 
#include <arpa/inet.h>

#define DNS_ETH_IPV4_UDP_LEN  (14 + 20 + 8)
#define DNS_ETH_IPV6_UDP_LEN  (14 + 40 + 8)

char myurl[64] = "";
//char myurl[64] = "www.sina.com.cn";
char url_cname[64] = "";
char url_ip[64] = "";

typedef unsigned short U16;
typedef unsigned int   U32;
typedef unsigned char  U8;

#pragma pack(push)
#pragma pack(1)
typedef struct _DNS_HDR
{
    U16 id;
    U16 tag;
    U16 numq;
    U16 numa;
    U16 numa1;
    U16 numa2;
}DNS_HDR;

typedef struct _DNS_QER
{
    U16 type;
    U16 classes;
}DNS_QER;

typedef struct _DNS_ANS
{
    U16 name;
    U16 type;
    U16 classes;
    U32 tol;
    U16 len;
    U8  data[0];    
}DNS_ANS;
#pragma pack(pop)

static void pkt_print(unsigned char *pkt, int len);

#if 0
void resolve(const unsigned char *recvMsg, int len, int len_recvMsg)
{
    int pos = len;
    int cnt = 12;
    
    while(pos < len_recvMsg) {
        unsigned char now_pos = recvMsg[pos+1];
        unsigned char retype = recvMsg[pos+3];
        unsigned char reclass = recvMsg[pos+5];
        unsigned char offset = recvMsg[pos+11];
        if(retype == 1) {
            if(now_pos == cnt && reclass == 1) {
                printf("%u.%u.%u.%u\n",recvMsg[pos+12],recvMsg[pos+13],recvMsg[pos+14],recvMsg[pos+15]);
            }
        }
        else if(retype == 5) {
            cnt = pos + 12 ;
        }
        pos = pos + 12 + offset;
    }
}
#endif

static int is_pointer(int in){
	return ((in & 0xc0) == 0xc0);
}

static void parse_dns_name(unsigned char *dns_head, unsigned char *ptr , char *out , int *len)
{
	int n , alen , flag;
	char *pos = out + (*len);
 
	for(;;){
		flag = (int)ptr[0];
               // printf("flag=%d\r\n", flag);
		if(flag == 0)
                {
                        //*pos = 0;
			break;
                }
		if(is_pointer(flag)){
                        //*pos = 0;
			n = (int)ptr[1];
			ptr = dns_head + n;
			parse_dns_name(dns_head,  ptr , out , len);
			break;
		}else{
			ptr++;
			memcpy(pos , ptr , flag);
			pos += flag;
			ptr += flag;
			*len += flag;
			if((int)ptr[0] != 0){
				memcpy(pos , "." , 1);
				pos += 1;
				(*len) += 1;
			}
		}
	}
 
}

void dns_answer_resolve(unsigned char *dns_head, unsigned char *msg, int len, int type, int *answer_len)
{
    DNS_ANS *dns_ans = (DNS_ANS *)msg;
   
    //printf("answer dns_ans->type=%d\r\n", ntohs(dns_ans->type));
    pkt_print(msg, len);

    if (dns_ans->type == ntohs(1))
    {
        /* host ip */
        sprintf(url_ip, 
               "%u.%u.%u.%u", 
               dns_ans->data[0],
               dns_ans->data[1],
               dns_ans->data[2],
               dns_ans->data[3]
                );
        printf("   ip: %s\r\n", url_ip);
    }
    else if (dns_ans->type == ntohs(5))
    {
        /* cname */
       int cname_len = 0;
       memset(url_cname, 0, sizeof(url_cname));
       // memcpy(url_cname, (char *)&(dns_ans->data[1]), dns_ans->len - 1);
        parse_dns_name(dns_head, &(dns_ans->data[0]), url_cname, &cname_len);
       // printf("cname: %s  cname_len=%d\r\n", url_cname, cname_len);
        printf("cname: %s\r\n", url_cname);
        //strcpy(url_cname, (char *)&(dns_ans->data[1]));
    }

    *answer_len = sizeof(DNS_ANS) + ntohs(dns_ans->len);

    return;
}

int dns_query_resolve(unsigned char *dns_head, unsigned char *msg, int len, int *query_len, int *type)
{
    int ret = 0;
    char url[64];
    int url_len = 0;
     
    memset(url, 0, sizeof(url));
    //url = (char *)(msg + 1);
    parse_dns_name(dns_head, msg, url, &url_len);
    //printf("query url:%s url_len=%d\r\n", url, url_len);
    pkt_print(msg, len);
    if (strcmp(url, myurl) != 0)
    {
        if (strcmp (url, myurl) != 0)
        {
            return -1;
        }
        else 
        {
            *type = 2; //host = cname
        }
    }
    else
    {
        *type = 1;  //host = myurl
    }

    *query_len = url_len + 2 + sizeof(DNS_QER);
 
    return 0;
}

void dns_head_resolve(unsigned char *msg, int len)
{
    /* resolve query num and answer num */
    int query_num = 0;
    int answer_num = 0;
    int query_len = 0;
    int ret = 0;
    int type = 0;
    unsigned char *pmsg = msg;
     DNS_HDR *dns_hdr = (DNS_HDR *)msg;
    int i = 0;
    int answer_len = 0; 
  
    query_num = ntohs(dns_hdr->numq);
    answer_num = ntohs(dns_hdr->numa);

    pkt_print(pmsg, len);

    if ((0 == query_num) || (answer_num == 0))
    {
      //  printf("error: query_num=%d, answer_num=%d\r\n", query_num, answer_num);
        return; 
    }
 //   printf("error: query_num=%d, answer_num=%d\r\n", query_num, answer_num);       
    pmsg += sizeof(DNS_HDR);
    
     pkt_print(pmsg, len-sizeof(DNS_HDR));
    ret = dns_query_resolve((unsigned char *)dns_hdr, pmsg, len - sizeof(DNS_HDR), &query_len, &type);
    if (ret != 0)
    {
        return;
    }

    // pkt_print(pmsg, len);

    pmsg += query_len;
    pkt_print(pmsg, len- sizeof(DNS_HDR) - query_len);
    for (i = 0; i < answer_num; i++)
    {
        dns_answer_resolve((unsigned char *)dns_hdr, pmsg, len - sizeof(DNS_HDR) - query_len - answer_len, type, &answer_len);
        pmsg += answer_len;
        if (url_ip[0] != '\0')
        {
           break;
        }
    }

    return;
}

void dns_resolve(const unsigned char *msg, int len)
{
     int head_len = 0;
     unsigned char *pmsg = msg;
     if (*(unsigned short *)(msg + 12) == ntohs(0x0800))
     {
         head_len = DNS_ETH_IPV4_UDP_LEN;
     }
     else if (*(unsigned short *)(msg + 12) == ntohs(0x86dd))
     {
         head_len = DNS_ETH_IPV6_UDP_LEN;
     }
     else
     {
         return;
     }

     pmsg += head_len;

     dns_head_resolve(pmsg, len - head_len);

     return;
}

static void pkt_print(unsigned char *pkt, int len)
{
#if 0 
     int i;
 printf("\r\n\r\n----------------------------\r\n");
  for(i=0; i<len; ++i)
  {
    printf(" %02x", pkt[i]);
    if( (i + 1) % 16 == 0 )
    {
      printf("\n");
    }
  }
  printf("\r\n");
#endif
  return;
}
 
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{  
  int * id = (int *)arg;
  int url_len = strlen("spool.grid.sinaedge.com")+2;  
  
#if 0  
  printf("id: %d\n", ++(*id));  
  printf("Packet length: %d\n", pkthdr->len);  
  printf("Number of bytes: %d\n", pkthdr->caplen);  
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));   
    
  int i;  
  for(i=0; i<pkthdr->len; ++i)  
  {  
    printf(" %02x", packet[i]);  
    if( (i + 1) % 16 == 0 )  
    {  
      printf("\n");  
    }  
  }  
#endif
    
 // printf("\n\n");  

 // printf("resolve ip:");
  dns_resolve(packet, pkthdr->len);
  memset(url_cname, 0, sizeof(url_cname));
  memset(url_ip, 0, sizeof(url_ip));
}  
  
int main(int argc, char** argv)  
{  
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;  
    
/*
  if (0 == argc)
  {
       printf("error: not a url");
       return 0;
  }
*/

  while (myurl[0] == '\0')
  {
      printf("please input a url:");
      scanf("%s", myurl);
      printf("\r\n");
  }
  printf("resolve %s\r\n", myurl);

  /* get a device */  
  devStr = pcap_lookupdev(errBuf);  
    
  if(devStr)  
  {  
    printf("success: device: %s\n", devStr);  
  }  
  else  
  {  
    printf("error: %s\n", errBuf);  
    exit(1);  
  }  
    
  /* open a device, wait until a packet arrives */  
  pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);  
    
  if(!device)  
  {  
    printf("error: pcap_open_live(): %s\n", errBuf);  
    exit(1);  
  }  
    
  /* construct a filter */  
  struct bpf_program filter;  
  pcap_compile(device, &filter, "udp src port 53", 1, 0);  
  pcap_setfilter(device, &filter);  
    
  /* wait loop forever */  
  int id = 0;  
  pcap_loop(device, -1, getPacket, (u_char*)&id);  
    
  pcap_close(device);  
  
  return 0;  
}
