#pragma once
/*
//Ѱ��tag-length-value �ṹ
��������:
1. tag ����������޵� 
2. length ռ1-3���ֽ�,����length��ֵ���ó��� ����-pos
3. length��ֵ��value�ĳ���ƫ��={0,tag�ĳ���,length�ĳ���,tag+length�ĳ���}

4. ��֤�׶�: ������֤����,Ȼ�����Ѿ��õ��ı��ĸ�ʽ�����н���,�õ�������ȷ��������Ŀ,��ȷ�� ����ͨ��һ����ֵ������
*/
#include <stdio.h>
#include <stdlib.h>
#include <set>
#include <algorithm>
#include <vector>
using namespace std;
char * NodeTypeString[] = {"", "Tag","Length","Value","Unknown","Follow" };
typedef enum { Tag = 1, Length = 2, Value = 3, Unk = 4, Follow = 5 } NodeType;
struct Field
{
	int len;
	char * data;
	Field()
	{
		len = 0;
		data = NULL;
	}
	Field(int len)
	{
		this->len = len;
		data = new char[len];
	}
	void copy(const unsigned char * src, int len)
	{
		for (int i = 0; i < len; i++)
		{
			data[i] = src[i];
		}
	}
	bool operator<(const Field & rh) const 
	{
		for (int i = 0; i < min(rh.len, this->len); i++)
		{
			if (data[i] < rh.data[i]) return 1;
			if (data[i] > rh.data[i]) return 0;
		}
		return this->len < rh.len;
	}
	bool operator==(const Field & rh) const
	{
		for (int i = 0; i < min(rh.len, this->len); i++)
		{
			if (data[i] != rh.data[i]) return 0;
		}
		return this->len == rh.len;
	}
};
template <typename T=Field>
struct Node
{
	NodeType type;
	int len;

	Node *child, *parent, *sibling;
	set<T> valueset;
	Node()
	{
		len = 0;

		type = NodeType::Unk;
		valueset.clear();
		child = parent = sibling=NULL;
	}
	void display(int level,Node<T> * node)
	{
		printf("\n");
		for (int i = 0; i < level; i++) printf("\t");
		if (node)
		{
			printf("Type:%s,len:%d\t", NodeTypeString[node->type], node->len);

			while (node->sibling)
			{
				node = node->sibling;
				printf("Type:%s,len:%d\t", NodeTypeString[node->type], node->len);
			}
			if (node->child)
			{
				display(level + 1, node->child);
			}
		}
	}
};
template <typename T=Field>
struct Node<T> * getTreeStruct(const vector< unsigned char *> & payload_dataset, const vector<unsigned int> & real_length, int thresholdValue)
//�������ṹ
/*
*	payload_dataset:���������غ�����,ע��!�غɿ�������ƫ�Ƶ�,��һ����tcp/udp��ԭʼ�غ�,������غ�Ӧ���Ǿ������ƽṹ�����ݰ�
	thresholdValue: һ��tag�ܹ�ȡ�õ���಻ͬ��ֵ
*/
{
	if (payload_dataset.size() <= 0) return NULL;
	int min_length = real_length[0];
	for (int i = 0; i < real_length.size(); i++)
	{
		if (min_length > real_length[i])
		{
			min_length = real_length[i];
		}
	}
	if (min_length <= 3) return NULL;
	for (int i = 1; i < min_length - 3; i++)
	//TLV�ṹ����Ҳ��ռ3���ֽڰ�!
	{

		set <Field> tags;
		for (int j = 0; j< payload_dataset.size(); j++)
		{
			Field tag(i);
			tag.copy(payload_dataset[j], i);
			tags.insert(tag);
		}
		if (tags.size() < thresholdValue)
		{
			printf("This can be a tag field,len:%d.\n",i);
		}
		else
			//��������ֵ,˵����Ͳ���һ��tag��,��ʱ�ͺ��п��ܴ���length�����ֽ�
		{
			if (i == 1)
				//һ������һ��tag.
			{
				printf("This can not be a tag.\n");
			}
			//���ܴ�i��ʼ����length,֮ǰ����tag

			//������ƫ�����Ƿ�����Ǹ�length,�����������
			i--;
			float ratio1 = 0.0,ratio2=0.0;//length�Ǽ����ֽ�
			for (int j = 0; j < payload_dataset.size(); j++)
			{
				if ((payload_dataset[j][i] + i+1) <= real_length[j])
				{
					ratio1 += 1;//һ���ֽڵı���
				}
				if ((payload_dataset[j][i - 1] * 256 + payload_dataset[j][i] + i+1) <= real_length[j])
				{
					ratio2 += 1;
				}
			}
			ratio1 /= payload_dataset.size();
			ratio2 /= payload_dataset.size();
			if (ratio2 > 0.8)
			{
				printf("This can be 2 byte length field.\n");
				Node<Field>* tagNode = new Node<Field>();
				Node<Field>* lenNode = new Node<Field>();


				tagNode->len = i - 1;
				tagNode->type = NodeType::Tag;
				lenNode->len = 2;
				lenNode->type = NodeType::Length;
				tagNode->sibling = lenNode;
				vector< unsigned char *>  new_payload_dataset,follow_payload;
				vector<unsigned int>  new_real_length,follow_real_length;
				for (int j = 0; j < payload_dataset.size(); j++)
				{
					if ((real_length[j] - (payload_dataset[j][i - 1] * 256 + payload_dataset[j][i] + i + 1)) >= 0)
					{
						Field tag(i - 1);
						tag.copy(payload_dataset[j], i - 1);
						tagNode->valueset.insert(tag);
						new_payload_dataset.push_back(payload_dataset[j] + i + 1);
						new_real_length.push_back(real_length[j] - i - 1);

						follow_payload.push_back(payload_dataset[j] + i + 1 + payload_dataset[j][i - 1] * 256 + payload_dataset[j][i] + i + 1);
						follow_real_length.push_back(real_length[j] - (payload_dataset[j][i - 1] * 256 + payload_dataset[j][i] + i + 1));
					}
				}
				Node<Field>* valNode = getTreeStruct(new_payload_dataset, new_real_length, thresholdValue);
				Node<Field>* followNode = getTreeStruct(follow_payload, follow_real_length, thresholdValue);
				if (valNode)
				{
					valNode->type = NodeType::Value;
					lenNode->sibling = valNode;
					if (followNode)
					{
						followNode->type = NodeType::Unk;
						valNode->sibling = followNode;
					}
				}
				Node<Field> * root = new Node<Field>();
				root->child = tagNode;
				tagNode->parent = root;
				lenNode->parent = root;
				if (valNode)
				{
					valNode->parent = root;
				}
				if (followNode)
				{
					followNode->parent = root;
				}
				return root;
			}
			else if (ratio1 > 0.8)
			{
				printf("This can be 1 byte length field.\n");

				Node<Field>* tagNode = new Node<Field>();
				Node<Field>* lenNode = new Node<Field>();


				tagNode->len = i ;
				tagNode->type = NodeType::Tag;
				lenNode->len = 1;
				lenNode->type = NodeType::Length;
				tagNode->sibling = lenNode;
				vector< unsigned char *>  new_payload_dataset, follow_payload;
				vector<unsigned int>  new_real_length, follow_real_length;
				for (int j = 0; j < payload_dataset.size(); j++)
				{
					Field tag(i);
					tag.copy(payload_dataset[j], i);
					tagNode->valueset.insert(tag);
					new_payload_dataset.push_back(payload_dataset[j] + i);
					new_real_length.push_back(real_length[j] - i);

					follow_payload.push_back(payload_dataset[j] + i +payload_dataset[j][i]);
					follow_real_length.push_back(real_length[j] - (payload_dataset[j][i] + i + 1));
				}
				Node<Field>* valNode = getTreeStruct(new_payload_dataset, new_real_length, thresholdValue);
				Node<Field>* followNode = getTreeStruct(follow_payload, follow_real_length, thresholdValue);
				if (valNode)
				{
					valNode->type = NodeType::Value;
					lenNode->sibling = valNode;
					if (followNode)
					{
						followNode->type = NodeType::Follow;
						valNode->sibling = followNode;
					}
				}
				Node<Field> * root = new Node<Field>();
				root->child = tagNode;
				return root;
			}
			else
			{
				printf("This cannot be a length field...\n");
				return NULL;
			}
		}
	}
	return NULL;
}