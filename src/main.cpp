#include <util.h>
#include <time.h>
#include "BaseTool.h"
#include "relu_reduction.h"

#define PCAPDIR "C:\\Users\\dk\\Desktop\\wechat_and_whatsapp\\8080"
Relu_Reduction relu;
float freq_threshold = 0.2;

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
int clean_pcap(char *pcapname, char * filter = "", char redirect = 0)
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
				relu.feed_payload(packet.data + offset, packet.len - offset);
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
int main()
{

	//int start = clock();
	//char pcapname[] = "1556411102.pcap";
	//clean_pcap(pcapname, "host 47.100.21.91 and (tcp or udp)", 1);
	//int end = clock();
	//freopen("CON", "w", stdout);
	//printf("Time Use:%d\n", end - start);
	//return 0;

	char PCAPDIR_[230] = { 0 };
	sprintf(PCAPDIR_, "%s\\*", PCAPDIR);
	vector<string> files = get_files_from_dir(PCAPDIR_, ".pcap");
	PCAPDIR_[strlen(PCAPDIR_) - 1] = 0;
	for (int i = 0; i < files.size(); i++)
	{
		char pcapname[256] = { 0 };
		freopen("CON", "w", stdout);
		sprintf(pcapname, "%s%s", PCAPDIR_, files[i].c_str());
		printf("(%0.3f/100)\t%s\n", i*100.0 / files.size(), pcapname);
		clean_pcap(pcapname);
	}
	relu.display_ansiic();
	vector< vector<unsigned long long> > item_recorders;
	for (int i = 0; i < files.size(); i++)
	{
		char pcapname[256] = { 0 };
		freopen("CON", "w", stdout);
		sprintf(pcapname, "%s%s", PCAPDIR_, files[i].c_str());
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
					relu.encode(packet.data + offset, packet.len - offset, item_recorders);
				}
			}
			else
			{
				break;
			}
		}
	}
	//生成频繁项集合
	vector< set< unsigned long long > > item_set;
	item_set.clear();
	map< unsigned long long, int > items;
	for (int i = 0; i < item_recorders.size(); i++)
	{
		item_set.push_back(set < unsigned long long >());
		for (int j = 0; j < item_recorders[i].size(); j++)
		{

			if (items.find(item_recorders[i][j]) == items.end())
			{
				items[item_recorders[i][j]] = 0;
			}
			if (item_set[i].find(item_recorders[i][j]) == item_set[i].end())
			{
				items[item_recorders[i][j]] += 1;
			}
			item_set[i].insert(item_recorders[i][j]);
		}
	}
	vector< set< fitem > > frequent_item;
	//过滤小于阈值的item
	frequent_item.push_back(set<fitem>());//长度为1的。
	for (auto it = items.begin(); it != items.end(); it++)
	{
		if (it->second > freq_threshold * item_recorders.size())
		{
			fitem item;
			item.data.push_back(it->first);
			frequent_item[0].insert(item);
		}
	}
	//
	frequent_item.push_back(set<fitem>());//长度为2的。

	for (auto it = frequent_item[0].begin(); it != frequent_item[0].end(); it++)
	{
		it++;
		auto it2 = it;
		it--;
		for (; it2 != frequent_item[0].end(); it2++)
		{
			int count = 0;
			for (int i = 0; i < item_set.size(); i++)
			{
				bool cond = true;
				for (int j = 0; j < it->data.size(); j++)
				{
					if (item_set[i].find(it->data[j]) == item_set[i].end())
					{
						cond = false;
						break;
					}
				}
				if (!cond) break;
				for (int j = 0; j < it2->data.size(); j++)
				{
					if (item_set[i].find(it->data[j]) == item_set[i].end())
					{
						cond = false;
						break;
					}
				}
				if (!cond) break;
				count += 1;
			}

			if (count > freq_threshold * item_recorders.size())
			{
				fitem item;
				for (int i = 0; i < it->data.size(); i++)
				{
					item.data.push_back(it->data[i]);
				}
				for (int i = 0; i < it2->data.size(); i++)
				{
					item.data.push_back(it2->data[i]);
				}
				frequent_item[1].insert(item);
			}
		}
	}


	system("pause");
	return 0;
}