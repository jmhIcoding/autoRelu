#include <util.h>
#include <time.h>
#include "BaseTool.h"
#include "relu_reduction.h"
#include "SuffixSearch.h"
#include "Cluster.h"
#define PCAPDIR "C:\\Users\\jmh081701\\Desktop\\80\\"
typedef void(*callback)(char *payload, int length);		//回调函数的函数指针

Relu_Reduction relu;
float freq_threshold = 0.8;

void print_payload(unsigned char *data, int len)
{
	for (int i = 0; i < len; i++)
	{
		printf("%0.2x", data[i]);
		if (i < (len - 1))
		{
			printf(" ");
		}
		else
		{
			printf("\n");
		}
	}
}
void display_rule(unsigned char * data, int len)
{
	for (int i = 0; i < len; i++)
	{
		printf("%c", data[i]);
	}
}
int gather_payload(const _packet& packet)
{
	ethII_header eth = eth_parser(packet.data);

	if (eth.type == 0x0800)
		//ip Ð­Òé
	{
		ip_header ip = ip_parser(packet.data + sizeof(ethII_header));//parse ip header
		if (ip.proto == 0x11)
			//udp
		{
			udp_header udp = udp_parser(packet.data + sizeof(ethII_header) + 4 * (ip.ver_ihl & 0xF));//parse udp header
			if (udp.len - 8)
			{
				//printf("%d.%d,", packet.timestamp, packet.usec);
				DbgPrint(ip_info, &ip);
				DbgPrint(udp_info, &udp);
				//printf("%d,", udp.len - 8);
				//print_payload(packet.data + sizeof(ethII_header)+4 * (ip.ver_ihl & 0xF) + 8, udp.len - 8);
				//printf("\n");
				return packet.len - (udp.len - 8) ;
				//return (int)packet.data + sizeof(ethII_header) + 4 * (ip.ver_ihl & 0xF) + 8;
			}
		}
		else if (ip.proto == 0x06)
			//tcp
		{
			tcp_header tcp = tcp_parser(packet.data + sizeof(ethII_header) + 4 * (ip.ver_ihl & 0xF));//parse tcp header
			int len = ip.tlen - 4 * (ip.ver_ihl & 0xF) - 4 * ((tcp.tcpHeader_reserve & 0xF0) >> 4);
			if (len > 0 && len <= 1460)
			{
				//printf("%d.%d,", packet.timestamp, packet.usec);
				DbgPrint(ip_info, &ip);
				DbgPrint(tcp_info, &tcp);
				//printf("%d,", len);
				//printf("\n");
				return packet.len - len ;
			}
			/*
			else if (len > 1460)
			{
				int i;
				for (i = 0; i < (len / 1460); i++)
				{
					printf("%d.%d,", packet.timestamp, packet.usec);
					DbgPrint(ip_info, &ip);
					DbgPrint(tcp_info, &tcp);
					printf("%d,", 1460);
					printf("\n");
				}
				if (i * 1460 < len)
				{
					printf("%d.%d,", packet.timestamp, packet.usec);
					DbgPrint(ip_info, &ip);
					DbgPrint(tcp_info, &tcp);
					printf("%d,", len - i * 1460);
					printf("\n");
				}
			}
			else if (len < 0)
				//need to frack.
			{
				int i;
				for (i = 0; i < (packet.len / 1460); i++)
				{
					printf("%d.%d,", packet.timestamp, packet.usec);
					DbgPrint(ip_info, &ip);
					DbgPrint(tcp_info, &tcp);
					printf("%d,", 1460);
					printf("\n");
				}
				if (i * 1460 < packet.len)
				{
					printf("%d.%d,", packet.timestamp, packet.usec);
					DbgPrint(ip_info, &ip);
					DbgPrint(tcp_info, &tcp);
					printf("%d,", packet.len - i * 1460);
					printf("\n");
				}
			
			*/
		}
	}
	return 0;
}
int loop_pcap(char * pcapname, char *filter,callback function)
{
	pcap_gather gather = pcap_gather(pcapname);
	int packetno = 1;
	while (true)
	{
		_packet packet;
		gather.get_next_packet(&packet);
		if (packet.data && packet.len)
		{
			int offset = gather_payload(packet);
			if (offset)
			{
				function((char *)packet.data + offset, packet.len - offset);
			}
			packetno++;
		}
		else
		{
			break;
		}
	}
	return 0;
}
void test()
{
	Relu_Reduction relus;
	unsigned long long rst;
	unsigned long long rawdata = 0x0102030405060708;
	rst = relus.hash((unsigned char*)&rawdata, 4);
}
int _main()
{
	SuffixSearch search(0.5);
	char *str1 = "abcdefg";
	char *str2 = "bcdefgh";
	char *str3 = "1234567";
	search.feed((unsigned char *)str1, strlen(str1));
	search.feed((unsigned char *)str2, strlen(str2));
	search.feed((unsigned char *)str3, strlen(str3));
	search.calc();
	system("pause");
	exit(0);
	return 0;
}
int main()
{
	char PCAPDIR_[230] = { 0 };
	sprintf(PCAPDIR_, "%s\\*", PCAPDIR);
	vector<string> files = get_files_from_dir(PCAPDIR_, ".pcap");
	PCAPDIR_[strlen(PCAPDIR_) - 1] = 0;
	SuffixSearch search(0.1);
	StatisticCluster cluster(10);
	vector<int> cdf(files.size()+1, 0);
	int packetno = 0;
	vector< unsigned char *> payload_buffer;
	vector<int >			payload_length;
	for (int i = 0; i <files.size(); i++)
	{
		char pcapname[256] = { 0 };
		freopen("CON", "w", stdout);
		sprintf(pcapname, "%s%s", PCAPDIR_, files[i].c_str());
		printf("(%0.3f/100)\t%s\n", i*100.0 / files.size(), pcapname);
		
		//read pcaps 
		pcap_gather gather = pcap_gather(pcapname);
		cdf[i] = packetno;
		while (true)
		{
			_packet packet;
			gather.get_next_packet(&packet);
			if (packet.data && packet.len)
			{
				//不同协议还需要解析
				packetno++;
				int offset = gather_payload(packet);
				if (offset)
				{
					//search.feed(packet.data + offset, packet.len - offset);
					cluster.feed(packet.data + offset, packet.len - offset);
					unsigned char * p = (unsigned char *)malloc(sizeof(char) * (packet.len - offset));
					memcpy(p, packet.data + offset, packet.len - offset);
					payload_buffer.push_back(p);
					payload_length.push_back(packet.len - offset);
				}
				
				//search.feed(packet.data, packet.len);
				
			}
			else
			{
				break;
			}
		}
	}
	cdf[files.size()] = packetno;
	//search.calc();
	cluster.kmean();
	for (int i = 0; i < cluster.clusters_id.size(); i++)
	{
		if (cluster.clusters_id[i].size())
		{
			SuffixSearch search(0.1);
			for (auto it = cluster.clusters_id[i].begin(); it != cluster.clusters_id[i].end(); it++)
			{
				for (int j = 0; j < files.size(); j++)
				{
					if (*it >= cdf[j] && *it < cdf[j + 1])
					{
						printf("%s:%d\n", files[j].c_str(), *it - cdf[j] +1  );
						search.feed(payload_buffer[*it],payload_length[*it]);
						break;
					}
				}
			}
			search.calc();
		}
	}
	system("pause");
	return 0;
}