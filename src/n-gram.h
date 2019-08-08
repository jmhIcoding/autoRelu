#include <stdio.h>
#include <set>
#include <vector>
#include <algorithm>
#include <utility>
#include <string>
#include <map>
using namespace std;

class basic_item
{
public:
	pair <int, int> pos;//位置信息
	const string * pdata;		//为了节省内存,也可以先把所有的string集中存储
};
class NGram
{
public :
	NGram(int _n):
		n(_n),sample_cnt(0)
	{
		;
	}
	void feed(char * payload, int len)
	{
		dataset.push_back({});
		for (int i = 0; i < (len - n); i++)
		{
			basic_item item;
			size_t pos=payload_buffer.find(payload+i,n);
			
			if (pos==payload_buffer.npos)
			{
				pos = payload_buffer.size();
				payload_buffer.append(payload + i, n);
				frequence_item_data.insert({ {pos,n},1.0 });
			}
			else
			{
				frequence_item_data[pair<int, int>{pos, n}] += 1.0;
			}
			item.pos.first = sample_cnt;
			item.pos.second = i;
			dataset[sample_cnt].push_back(item);
		}
		sample_cnt += 1;
	}
public:
	int n;
	map<pair<int,int>, float > frequence_item_data;
	vector< vector< basic_item> > dataset;
	int sample_cnt;
	string payload_buffer;
};