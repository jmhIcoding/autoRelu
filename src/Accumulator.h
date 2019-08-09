#pragma once
#include <stdio.h>
#include <string>
#include <vector>
#include "LengthField.h"
#define EXP 1e-7
using namespace std;
float calc_entropy(const vector<int> & values,int bit_length)
{
	float rst = 0;
	map<int, float> frequency_count;
	for (int i = 0; i < values.size(); i++)
	{
		if (frequency_count.find(values[i]) == frequency_count.end())
		{
			frequency_count[values[i]] = 1.0;
		}
		else
		{
			frequency_count[values[i]] += 1.0;
		}
	}
	for (auto it = frequency_count.begin(); it != frequency_count.end(); it++)
	{
		it->second /= (values.size() + EXP);
		rst += - it->second *log(it->second);
	}
	return rst/(8 * bit_length);
}
void FindAccumulatorField(const vector< unsigned char *> & payload_dataset, const vector<int> & real_length)
{
	//寻找real_length最大值
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
		//从一个字节到4个字节
		vector<int> fieldvalue_vector;
		for (int offset = 0; offset < max_length; offset++)
		{
			for (char little_end = 0; little_end <= 1; little_end++)
			{
				fieldvalue_vector.clear();
				for (int i = 0; i < real_length.size(); i++)
				{
					if ((offset + field_length) < real_length[i])
					{
						
						int fieldvalue = extract_int(payload_dataset[i] + offset, field_length, little_end);
						
						fieldvalue_vector.push_back(fieldvalue);
					}
				}


				/*if (offset == 20)
				{
					__asm
					{
						int 3;
					}
				}*/
				vector<int> values;
				for (int i = fieldvalue_vector.size() - 1; i > 0; i--)
				{
					fieldvalue_vector[i] = fieldvalue_vector[i] - fieldvalue_vector[i - 1];
					if (fieldvalue_vector[i] > 0)
					{
						values.push_back(fieldvalue_vector[i]);
					}
				}
				if (values.size()*1.0 / real_length.size() < 0.6)
					//这种字段必须得是绝大数数据包都拥有的
				{
					continue;
				}
				float entropy = calc_entropy(values,field_length);

				printf("offset :%d ,size:%d, entropy : %0.5f, order:%d \n", offset,field_length, entropy,little_end);
			}
		}

	}
}