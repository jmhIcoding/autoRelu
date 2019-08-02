#include <map>
#include <vector>
#include <utility>
#include <algorithm>
#include <set>
using namespace std;
#ifndef RELU_REDUCTION_HH
#define RELU_REDUCTION_HH
typedef pair<unsigned long long, int > PAIR;
struct fitem
{
	vector<unsigned long long > data;
	bool operator<(const fitem & rh) const
	{
		int len = min(rh.data.size(), data.size());
		for (int i = 0; i < len; i++)
		{
			if (data[i] < rh.data[i])
			{
				return 1;
			}
			if (data[i] > rh.data[i])
			{
				return 0;
			}

		}
		if (data.size() < rh.data.size())
		{
			return 1;
		}
		if (data.size() > rh.data.size())
		{
			return 0;
		}
		return 0;
	}
};
bool cmp_by_value(const PAIR & lh, const PAIR & rh)
{
	return lh.second > rh.second;
}
class Relu_Reduction
{

public:
	Relu_Reduction(int _key_len=4):
		key_len(_key_len)
	{
		frequency.clear();
	}
	static unsigned long long hash(unsigned char * pdata, unsigned char length)
	{
		unsigned long long rst = 0;
		for (int i = 0; i < length; i++)
		{
			rst =rst *256+ pdata[i] ;
		}
		return rst;
	}
	void merge(map<unsigned long long, int> &tmp_frequency)
		//将新得到的频次结果和原来的结果进行合并
	{
		for (map<unsigned long long, int>::iterator it = tmp_frequency.begin(); it != tmp_frequency.end(); it++)
		{
			frequency[it->first] += it->second;
		}
	}
	void feed_payload(unsigned char *payload, int length,int _key_len=0)
		//输入一个包的载荷,计算这个payload的频次情况
		//key_len ： 指示提取的n-gram
	{
		if (_key_len == 0)
		{
			_key_len = key_len;
		}
		if (_key_len < 2 || _key_len > 8)
		{
			return;
		}
		unsigned long long key = 0;
		map<unsigned long long, int> tmp_frequency;
		tmp_frequency.clear();
		for (int i = 0; i < (length-_key_len); i++)
		{
			key = hash(payload + i, _key_len);
			if (tmp_frequency.find(key) == tmp_frequency.end())
			{
				tmp_frequency[key] += 1;
			}
		}

		//merge
		merge(tmp_frequency);
	}
	void display_hex()
	{
		char * key;
		for (map<unsigned long long, int>::iterator it = frequency.begin(); it != frequency.end(); it++)
		{
			key = (char *)&it->first;
			for (int i = 0; i < key_len; i++)
			{
				printf("%0.2X ", key[i]);
			}
			printf(":%d\n", it->second);
		}
	}
	void display_ansiic()
	{
		char * key;
		vector<PAIR> vec(frequency.begin(), frequency.end());
		sort(vec.begin(), vec.end(), cmp_by_value);
		for (int i =0;i<min(500,(int)vec.size());i++)
		{
			key = (char *)&vec[i].first;
			for (int i = key_len-1; i >=0; i--)
			{
				printf("%c", key[i]);
			}
			printf(":%d\n", vec[i].second);
			item.insert(vec[i].first);
		}
	}
	void encode(unsigned char * pdata, int length, vector<  vector< unsigned long long> > & item_records )
	{
		item_records.push_back({});
		for (int i = 0; i < length - key_len; i++)
		{
			unsigned long long key = hash(pdata + i, key_len);
			if (item.find(key) != item.end())
			{
				item_records[item_records.size() - 1].push_back(key);
			}
		}
	}
private:
	map<unsigned long long, int> frequency;
	//long long 8个字节,long long的最高位对应于第一个字节
	set<unsigned long long> item;//频繁出现的项
	unsigned char key_len;
};
#endif