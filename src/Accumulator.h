#pragma once
#include <stdio.h>
#include <string>
#include <vector>
#include "LengthField.h"
#define EXP 1e-7
using namespace std;
void FindAccumulatorField(const vector< unsigned char *> & payload_dataset, const vector<int> & real_length)
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

				if (fieldvalue_vector.size()*1.0 / real_length.size() < 0.8)
					//�����ֶα�����Ǿ��������ݰ���ӵ�е�
				{
					continue;
				}
				for (int i = fieldvalue_vector.size() - 1; i > 0; i--)
				{
					fieldvalue_vector[i] = fieldvalue_vector[i] - fieldvalue_vector[i - 1];
				}
			}
		}

	}
}