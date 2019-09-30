#pragma once
#include <stdio.h>
#include <string>
#include <vector>
#define EXP 1e-7
using namespace std;
int extract_int(unsigned char * p, int length,char little_end )
{
	int rst = 0;
	if (little_end == 0)
	{
		for (int i = 0; i < length; i++)
		{
			rst = rst * 256 + p[i];
		}
	}
	else
	{
		for (int i = length-1; i >= 0; i--)
		{
			rst = rst * 256 + p[i];
		}
	}
	return rst;
}

template <typename T>
pair<float, pair<float,float> >person_sample_correlation_coefficient(const vector<T> & x, const vector<T> & y)
{
	//�������������,ʹ�� https://en.wikipedia.org/wiki/Pearson_correlation_coefficient �Ķ���
	float rxy = 0;
	int n = x.size();
	double sum_xy = 0, sum_x = 0, sum_y = 0, sum_xx = 0, sum_yy = 0;
	double avg_x = 0, avg_y = 0;
	float k = 0, b = 0;
	for (int i = 0; i < n; i++)
	{
		sum_xy += x[i] * y[i];
		sum_x += x[i];
		sum_y += y[i];
		sum_xx += x[i] * x[i];
		sum_yy += y[i] * y[i];

	} 
	avg_x = sum_x / (EXP+n);
	avg_y = sum_y / (EXP + n);

	rxy = (n * sum_xy - sum_x * sum_y) /( sqrt((n*sum_xx - sum_x * sum_x)*(n*sum_yy - sum_y * sum_y)) + EXP);
	k = (sum_xy - n * avg_x * avg_y) / (EXP + sum_xx - n * avg_x * avg_x);//����������ϵ�б��
	b = avg_y - k * avg_x;	//������ϵĽؾ�
	return { rxy,{k,b} };
}
void FindLengthField(const vector< unsigned char *> & payload_dataset, const vector<int> & real_length)
{
	//Ѱ��real_length���ֵ
	int max_length = 0;
	for (int i = 0; i < real_length.size(); i++)
	{
		if (real_length[i] > max_length)
		{
			max_length = real_length[i];
			if (max_length >= 1460)
			{
				break;
			}
		}
	}
	for (int field_length = 1; field_length <= 4; field_length++)
	{
		//��һ���ֽڵ�4���ֽ�
		vector<int> length_vector;
		vector<int> fieldvalue_vector;
		for (int offset= 0; offset < max_length; offset++)
		{

			for (char little_end = 0; little_end <= 1; little_end++)
			{
				length_vector.clear();
				fieldvalue_vector.clear();
				for (int i = 0; i < real_length.size(); i++)
				{
					if ((offset + field_length) < real_length[i])
					{
						length_vector.push_back(real_length[i]);
						fieldvalue_vector.push_back(extract_int(payload_dataset[i] + offset, field_length, little_end));
					}
				}
				if (length_vector.size()*1.0 / real_length.size() < 0.8)
					//�����ֶα�����Ǿ��������ݰ���ӵ�е�
				{
					continue;
				}
				pair<float, pair <float, float> > rxy = person_sample_correlation_coefficient(fieldvalue_vector, length_vector);
				if (abs(rxy.first) > 0.6  && abs(rxy.first) < 1.1)
				{
					printf("offset:%d,size:%d can be, coefficient :%0.5f, k:%0.5f,b:%0.5f,", offset, field_length, rxy.first, rxy.second.first, rxy.second.second);
					if (little_end==1)
					{
						printf("network_ending\n");
					}
					else
					{
						printf("not-network_ending\n");
					}
				}

			}
		}
		
	}
}