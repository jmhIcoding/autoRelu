#pragma once
#ifndef CLUSTERHHH
#define CLUSTERHHH
#include <vector>
#include <algorithm>
#include <cmath>
#include <set>
#include <random>
#include <time.h>

using namespace std;
#define EXP (1e-9)
typedef float(*similarity_function)(const vector <float> & lh, const vector <float> & rh);

float cosine_similarity(const vector <float > & lh, const vector <float> & rh)
{
	float rst = 0;
	float frac_head = 0, frac_tail_1=0, frac_tail_2 = 0;
	if (lh.size() != rh.size())
	{
		return 0.0;
	}
	for (int i = 0; i < lh.size(); i++)
	{
		frac_head += lh[i] * rh[i];
		frac_tail_1 += lh[i] * lh[i];
		frac_tail_2 += rh[i] * rh[i];
	}
	return rst = frac_head / ((sqrt(frac_tail_1 * frac_tail_2)) + EXP);
}

float jaccard_similarity(const vector< float> & lh, const vector <float> & rh)
{
	return 0;
}
float person_similarity(const vector<float> & lh, const vector<float> & rh)
{
	return 0;
}
class StatisticCluster
{
public:
	StatisticCluster(int k)
		:clusters_id(k,set<int>()),
		clusters_core(k,vector <float> ())
	{
		sample_cnt = 0;
		cluster_cnt = k;
		dataset.clear();
	}
	void feed(unsigned char *_payload, int length)
	{
		if (_payload && length)
			dataset.push_back(vector<float>(256, 0.0));
		unsigned char* payload = (unsigned char *)_payload;
		for (int i = 0; i < length; i++)
		{
			dataset[sample_cnt][payload[i]] += 1;
		}
		for (int i = 0; i < length; i++)
		{
			dataset[sample_cnt][payload[i]] /= (length + EXP);
		}
		sample_cnt += 1;
	}
	void kmean(const vector < vector <float> > * p_dataset = NULL, similarity_function sim_func=cosine_similarity,
		vector< set<int> >* p_clusters_id=NULL,
		vector< vector< float> > * p_clusters_core=NULL)
		//运行kmeans-算法
		//cluster_cnt	:	类簇数目
		//p_dataset		:	数据集
		//sim_func		：	相似度函数

	{
		if (p_dataset == NULL)
		{
			p_dataset = & this->dataset;
		}
		if (p_clusters_id == NULL)
		{
			p_clusters_id = &this->clusters_id;
		}
		if (p_clusters_core == NULL)
		{
			p_clusters_core = &this->clusters_core;
		}
		const vector < vector< float> > & dataset = *p_dataset;
		vector< set<int> > & clusters_id = *p_clusters_id;
		vector < vector <float> > & clusters_core = *p_clusters_core;
		//初始化的类簇
		for(int i =0;i<cluster_cnt;i++)
		{
			int index = rand() % dataset.size();
			clusters_core[i]=dataset[index];
			clusters_id[i].insert(index);
		}
		vector<int> id2cluster(dataset.size(),0);
		char flag = 1;
		while (flag)
		{
			flag = 0;
			for (int i = 0; i < dataset.size(); i++)
			{
				float max_similarity = 0.0;
				int cluster = -1;
				for (int j = 0; j < cluster_cnt; j++)
				{
					float tmp = sim_func(dataset[i], clusters_core[j]);
					if (tmp > max_similarity)
					{
						max_similarity = tmp;
						cluster = j;
					}
				}
				if (cluster != id2cluster[i])
				{
					flag = 1;
					////更新类心,此处更新类心会很难收敛

					//for (int j = 0; j < clusters_core[cluster].size(); j++)
					//{
					//	clusters_core[cluster][j] = (clusters_core[cluster][j] * clusters_id[cluster].size() + dataset[i][j]) / ((clusters_id[cluster].size() + 1) + EXP);
					//	clusters_core[id2cluster[i]][j] = (clusters_core[id2cluster[i]][j] * clusters_id[id2cluster[i]].size() - dataset[i][j]) / (clusters_id[id2cluster[i]].size() - 1 + EXP);
					//}
					clusters_id[cluster].insert(i);
					clusters_id[id2cluster[i]].erase(i);
					id2cluster[i] = cluster;
				}
			}
			if (flag)
			{
				//更新每个类簇的簇心
				for (int cluster = 0; cluster < cluster_cnt; cluster++)
				{
					//对于每一个类,更新类心
					for (int i = 0; i < clusters_core[cluster].size(); i++)
					{
						clusters_core[cluster][i] = 0.0;
						for (auto it = clusters_id[cluster].begin(); it != clusters_id[cluster].end(); it++)
						{
							clusters_core[cluster][i] += dataset[*it][i];
						}
						clusters_core[cluster][i] /= (clusters_id[cluster].size() + EXP);
					}
				}
			}
		}

	}
	void LocalSensetiveHash()
	{
		;
	}

public:
	vector< vector<float>  > dataset;
	vector< set <int > > clusters_id;
	vector< vector< float> > clusters_core;
	int sample_cnt;	//样本个数
	int cluster_cnt;//类簇的个数
};
#endif