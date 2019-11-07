#ifdef WIN32
#include <util.h>
#else
#include "util.h"
#endif
#include "config.h"
#include <time.h>
#include "BaseTool.h"		//
#include "SuffixSearch.h"	//包含这两个头文件
#define PCAP_START 0
#define PCAP_END 1

int gather_payload(const _packet& packet)
				//这个函数在实际使用中可以不需要,只用于从pcap文件中提取数据包的载荷偏移量
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
		}
	}
	return 0;
}
int main()
{
	extern const char * pcap_dir;
	extern float freq_threshold;//设置一个过滤阈值,表示把 N个数据包里面，出现次数超过freq_threshold * N 的字符子串提取出来,一个子串如果在一个数据包出现
							//多次,那么只当做一次来统计。
	extern const char * output_file;

	char PCAPDIR_[230] = { 0 };
	sprintf(PCAPDIR_, "%s//", pcap_dir);
	vector<string> files = get_files_from_dir(PCAPDIR_, ".pcap");//获取某个目录下的所的pcap文件
	printf("Get %d files from %s\n",files.size(),PCAPDIR_);
	PCAPDIR_[strlen(PCAPDIR_) - 1] = 0;
	SuffixSearch search(freq_threshold);			     //关键类
	vector<int> cdf(files.size()+1, 0);
	int packetno = 0;
	int packetCnt= 0;
	vector< unsigned char *> payload_buffer;
	vector<int >			payload_length;
	char logfile[256] = { 0 };
	
	for (int i = 0; i <files.size(); i++)
	{
		char pcapname[256] = { 0 };

		sprintf(pcapname, "%s%s", PCAPDIR_, files[i].c_str());
		printf("Loading pcaps...(%0.3f/100)\t%s\n", i*100.0 / files.size(), pcapname);
		
		//read pcaps 
		pcap_gather gather = pcap_gather(pcapname);
		packetno = 0;
		while (true)
		{
			_packet packet;
			gather.get_next_packet(&packet);
			if (packet.data && packet.len)
			{
				//不同协议还需要解析
				
				int offset = gather_payload(packet);
				if (offset)
				{
					if (!(packetno >= PCAP_START && packetno < PCAP_END))
					{
						break;
					}
					search.feed(packet.data + offset, packet.len - offset);//灌入载荷
					packetno++;
					packetCnt++;
					
				}	
			}
			else
			{
				break;
			}
		}
	}
	vector<string > frequent_str;
	vector<int> occurance;
	search.calc(frequent_str,occurance);
	printf("Analysing........\n");
	freopen(output_file,"w",stdout);
	for (int i = 0; i < occurance.size(); i++)
	{
		printf("Occurance : %d/%d\n", occurance[i],packetCnt);
		printf("Length : %d\n", frequent_str[i].size());
		printf("---------------------------------------------\n");
		printf("Asiic Format:\n");
		for (int index = 0; index < frequent_str[i].size(); index++)
		{
			printf("%c", frequent_str[i].c_str()[index]);
		}
		printf("\nHex Format:\n");
		for (int index = 0; index < frequent_str[i].size(); index++)
		{
			unsigned char ch = frequent_str[i].c_str()[index];
			printf("0x%0.2X ",ch);
		}
		printf("\n===========================================\n");
	}
	return 0;
}
