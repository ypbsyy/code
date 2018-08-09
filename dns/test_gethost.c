#include <netdb.h>
 #include <string.h>
 #include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
 #include <sys/socket.h> 


 int main(int argc, char *argv[])
 {
    struct hostent *ht=NULL;

    /* 查询的主机域名 */
    char host[]="www.sina.com.cn";

 #if 1
    struct hostent *ht1=NULL, *ht2=NULL;
    char host1[]="www.qq.com";
    /* 查询主机www.sina.com.cn */
    ht1 = gethostbyname(host);
    ht2 = gethostbyname(host1);//函数的不可重入性，前者结果已经被覆盖
    int j = 0;

 #else
    struct in_addr in;
    in.s_addr = inet_addr("60.215.128.140");
    ht = gethostbyaddr(&in, sizeof(in), AF_INET);
 #endif
 for(j = 0;j<2;j++){
    if(j == 0)
        ht = ht1;
    else
        ht =ht2;

    printf("----------------------\n");

    if(ht){
        int i = 0;
        printf("get the host:%s addr\n",host);  /* 原始域名 */
        printf("name:%s\n",ht->h_name);         /* 名称 */

        /*协议族AF_INET为IPv4或者AF_INET6为IPv6*/
        printf("type:%s\n",ht->h_addrtype==AF_INET?"AF_INET":"AF_INET6");

        /* IP地址的长度 */
        printf("legnth:%d\n",ht->h_length); 
        /* 打印IP地址 */
        for(i=0;;i++){
            if(ht->h_addr_list[i] != NULL){/* 不是IP地址数组的结尾 */
                printf("IP:%s\n",inet_ntoa(*(struct in_addr *)(ht->h_addr_list[i]))); /*打印IP地址*/
            }   else{/*达到结尾*/
                break;  /*退出for循环*/
            }
        }

        /* 打印域名地址 */
        for(i=0;;i++){/*循环*/
            if(ht->h_aliases[i] != NULL){/* 没有到达域名数组的结尾 */
                printf("alias %d:%s\n",i,ht->h_aliases[i]); /* 打印域名 */
            }   else{/*结尾*/
                break;  /*退出循环*/
            }
        }
    }   
}
    return 0;
 }
