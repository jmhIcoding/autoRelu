//头文件,用于对winpcap里面的函数进行封装
#ifndef UTIL_H_INCLUDED
	#define UTIL_H_INCLUDED
#ifndef WPCAP
#define	WPCAP
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap-stdinc.h>
#include <pcap.h>
#include <protocol.h>
#include <vector>
#include <set>
#include <map>
#include <openssl\x509.h>
#include <openssl\x509v3.h>
#include <openssl\bio.h>
#include <openssl\bn.h>
#include <openssl\x509_vfy.h>
#include <openssl\pem.h>
#include <string.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "openssl.lib")
#pragma comment(lib, "libcrypto_static.lib")
#pragma pack(1)


using namespace std;

#define eth_info	0x01
#define ip_info		0x02
#define tcp_info	0x04
#define udp_info	0x08
#define dns_info	0x10
#define http_info	0x20
#define https_info	0x40
#define raw_packet_info 0x80
//#define DEBUG_INFO (eth_info | ip_info | tcp_info | udp_info | dns_info | http_info | https_info)

#define DEBUG_INFO (0)
ethII_header  eth_parser(unsigned char * pkt_data);//以太网的解析
ip_header ip_parser(unsigned char *  ip_data);//ip报文的解析 ,
tcp_header tcp_parser(unsigned char * tcp_data);//tcp报文的解析
udp_header udp_parser(unsigned char * udp_data);//udp报文的解析
void display(unsigned char * pkt_data, int len, int nextline = 16);//包内容打印
void DbgPrint(int level, void *header);
struct _packet
{
	int len;
	long int timestamp;//second
	long int usec;//u second .
	unsigned char * data;
	_packet() :len(0), timestamp(0), data(0)
	{
		;
	}

};

class pcap_gather
{

public:
	pcap_gather(char * pcapfile);//从文件中读包
	pcap_gather(int interfaces);//从网卡中抓取实时的报文
	void set_filter(char *filter, pcap_t * pt = NULL);
	vector< _packet> get_packets(pcap_t * pt = NULL);//获取全部报文,主要用于通过文件获取报文
	void get_next_packet(_packet * packet, pcap_t * pt = NULL);//一个一个的获取报文
	~pcap_gather()
	{
		if (pcapt)
		{
			pcap_close(pcapt);
		}
	}
public:
	pcap_t * pcapt;
	char errBuf[2048];
};

#endif // UTIL_H_INCLUDED
