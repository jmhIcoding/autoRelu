#pragma once
#ifndef SUFFIXSEARCH
#define SUFFIXSEARCH
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <stdlib.h>
#include <set>
#include <string>
using namespace std;

#define maxn (1460 * 10)
#define maxPacket (1000)
char tmpStr[1500];
int cmp(unsigned int *r, int a, int b, int l)
//字符串比较函数
{
	return r[a] == r[b] && r[a + l] == r[b + l];
}

void da( unsigned int *r,   int *sa, int n, int m, unsigned int *wa, unsigned int *wb, unsigned  int *ws,  unsigned int *wv)
//根据输入串,计算它的后缀数组
{
	int i, j, p;
	unsigned int *x = wa, *y = wb, *t;
	for (i = 0; i<m; i++) ws[i] = 0;
	for (i = 0; i < n; i++)
	{
		//if (r[i] > 1200)
		//{
		//	__asm
		//	{
		//		int 0x3;
		//	}
		//}
		ws[x[i] = r[i]]++;
		//if (x[i] > 1200)
		//{
		//	__asm
		//	{
		//		int 0x3;
		//	}
		//}
	}
	for (i = 1; i<m; i++) ws[i] += ws[i - 1];
	for (i = n - 1; i >= 0; i--) sa[--ws[x[i]]] = i;
	for (j = 1, p = 1; p<n; j *= 2, m = p)
	{
		for (p = 0, i = n - j; i<n; i++) y[p++] = i;
		for (i = 0; i<n; i++) if (sa[i] >= j) y[p++] = sa[i] - j;
		for (i = 0; i<n; i++) wv[i] = x[y[i]];
		for (i = 0; i<m; i++) ws[i] = 0;
		for (i = 0; i<n; i++) ws[wv[i]]++;
		for (i = 1; i<m; i++) ws[i] += ws[i - 1];
		for (i = n - 1; i >= 0; i--) sa[--ws[wv[i]]] = y[i];
		for (t = x, x = y, y = t, p = 1, x[sa[0]] = 0, i = 1; i<n; i++)
			x[sa[i]] = cmp(y, sa[i - 1], sa[i], j) ? p - 1 : p++;
	}
	return;
}

void calheight( unsigned  int *r,   int *sa, int n,  int * rank,  int *height)
//根据输入串和后缀数组,计算rank和height
{
	int i, j, k = 0;
	for (i = 1; i <= n; i++) rank[sa[i]] = i;
	for (i = 0; i<n; height[rank[i++]] = k)
	for (k ? k-- : 0, j = sa[rank[i] - 1]; r[i + k] == r[j + k]; k++);
	return;
}
int check(int tlen,char  *flag,  int *height,  int *cate,  int *sa,int len,int n,int threshold)
{
	int i, j, k, cnt;
	i = j = 1;
	while (i <= len && j <= len)
	{
		for (k = 0; k<n; k++)
			flag[k] = 0;
		while (height[i]<tlen && i <= len)
			i++;
		j = i;
		while (height[j] >= tlen && j <= len)
			j++;
		//if (j - i + 2 <= n / 2)
		//{
		//	i = j;
		//	continue;
		//}
		for (k = i - 1; k<j; k++)
		{
			if (cate[sa[k]] != -1)
				flag[cate[sa[k]]] = 1;
		}
		for (cnt = 0, k = 0; k<n; k++)
			cnt += flag[k];
		if (cnt> threshold)
			return 1;
		i = j;
	}
	return 0;
}

void print(int tlen,  char *flag,   int *height,   int *cate,   int *sa, int len, int n, int threshold, unsigned int *a ,set< string > &pattern_strs,set< int> & pattern_start)
{
	if (tlen == 0)
	{
		printf("?\n");
		return;
	}
	int i, j, k, cnt;
	i = j = 1;
	while (i <= len && j <= len)
	{
		for (k = 0; k<n; k++)
			flag[k] = 0;
		continue_start:
		while (height[i]<tlen && i <= len)
			i++;
		j = i;
		while (height[j] >= tlen && j <= len)
			j++;
		if (pattern_start.find(sa[i]) != pattern_start.end())
		{
			i = j;
			//goto continue_start;
			continue;
		}

		//if (j - i + 2 <= n / 2)
		//{
		//	i = j;
		//	continue;
		//}
		for (k = i - 1; k<j; k++)
		{
			if (cate[sa[k]] != -1)
				flag[cate[sa[k]]] = 1;
		}
		for (cnt = 0, k = 0; k<n; k++)
			cnt += flag[k];
		if (cnt>threshold)
		{


			for (k = 0; k<tlen; k++)
				tmpStr[k] = a[sa[i] + k];
			tmpStr[tlen] = 0;
			char substr = 0;

			for (auto it = pattern_strs.begin(); it != pattern_strs.end() ; it++)
			{
				if (it->find(tmpStr, 0, tlen) != string::npos)
				{
					substr = 1;
					break;
				}
			}
			if (substr == 0)
			{
			
				pattern_strs.insert(string(tmpStr,tlen));
				pattern_start.insert(sa[i]);
				printf("Occurance : %d\n", cnt);
				printf("Asiic Format:\n");
				printf("%s", tmpStr);
				printf("\nHex Format:\n");
				for (int index = 0; index < tlen; index++)
				{
					unsigned char ch = tmpStr[index];
					printf("0x%0.2X ",ch-1);
				}
				printf("\n===========================================\n");
			}
		}
		i = j;
	}
}
class SuffixSearch
{
public:
	SuffixSearch(float _threshold) :fthreshold(_threshold), 
		up(290),
		mx(1), 
		i(0), j(0),
		n(0),
		a(0),cate(0),sa(0),rank(0),height(0),wa(0),wb(0),wv(0),ws(0),flag(0)

	{
		a = ( unsigned  int *)malloc(sizeof( unsigned int)*maxn);
		cate = (  int *)malloc(sizeof(  int)*maxn);
		allocate = maxn;
		used = 0;	
		pattern_str.clear();
		pattern_start.clear();
	}
	~SuffixSearch()
	{
		if (sa)
			free(sa);
		if (a)
			free(a);
		if (cate)
			free(cate);
		if (rank)
			free(rank);
		if (height)
			free(height);
		if (wa)
			free(wa);
		if (wb)
			free(wb);
		if (wv)
			free(wv);
		if (ws)
			free(ws);
		if (flag)
			free(flag);
	}
public:
	void feed(unsigned char  * payload_str, int length)
		//填充新的载荷内容
	{
		len1 = length;
		if (len1 > mx)
		{
			mx = len1;
		}
		while (!((allocate - used- 10) > len1))
			//内存不足,先分配内存
		{
			allocate +=max(maxn,allocate); //倍增申请内存
			int * p_cate = (int *)malloc(sizeof(int)* allocate);
			unsigned int * p_a = (unsigned int *)malloc(sizeof(unsigned int)* allocate);
			if (p_cate == NULL || p_a == NULL)
			{
				printf("Cannot allocate more memory!!!\n");
				__asm
				{
					int 0x3;
				}
			}
			memset(p_cate, 0, sizeof(unsigned int)*allocate);
			memset(p_a, 0, sizeof(unsigned int)*allocate);
			memcpy(p_cate, cate, used * sizeof(int));
			memcpy(p_a, a, used * sizeof(unsigned int));
			free(a);
			free(cate);
			cate = p_cate;
			a = p_a;
		}
		for (k = 0; k < len1; k++)
		{
			cate[j] = i;
			a[j++] = 1+payload_str[k] ;
		}
		cate[j] = -1;
		a[j++] = up + i;

		i++;
		n++;
		used += len1 + 1;
	}
	void calc()
	{
		//申请辅助内存
		if (n>1)
		{
			sa = (int *)malloc(sizeof(int)*allocate);
			memset(sa, 0, sizeof(int)* allocate);

			rank = (int *)malloc(sizeof(int)*allocate);
			memset(rank, 0, sizeof(int)* allocate);

			height = (int *)malloc(sizeof(int)*allocate);
			memset(height, 0, sizeof(int)* allocate);

			wa = (unsigned int *)malloc(sizeof(unsigned  int)*allocate);
			memset(wa, 0, sizeof(unsigned int)* allocate);

			wb = (unsigned int *)malloc(sizeof(unsigned int)*allocate);
			memset(wb, 0, sizeof(unsigned int)* allocate);

			wv = (unsigned int *)malloc(sizeof(unsigned int)*allocate);
			memset(wv, 0, sizeof(unsigned int)* allocate);

			ws = (unsigned  int *)malloc(sizeof(unsigned int)*allocate);
			memset(ws, 0, sizeof(unsigned int)* allocate);

			flag = (char *)malloc(sizeof(char)*(n + 10));
			memset(flag, 0, sizeof(char)* (n + 10));
			//计算
			a[--j] = 0;
			len = j;
			threshold = n * fthreshold;
			da(a, sa, len + 1, 300 + n, wa, wb, ws, wv);
			calheight(a, sa, len, rank, height);
			solve();
		}
	}
private:
	void solve()
	{
		int l, r, ans, mid;
		l = 0, r = mx;
		while (l <= r)
		{
			mid = (l + r) >> 1;
			if (check(mid,flag,height,cate,sa,len,n,threshold))
				l = mid + 1;
			else
				r = mid - 1;
		}
		ans = r;
		//print(30, flag, height, cate, sa, len, n, threshold, a,pattern_str);
		for (; ans > 10; ans--)
		{
			//printf("%d.....\n", ans);//...
			print(ans, flag, height, cate, sa, len, n, threshold, a,pattern_str,pattern_start);
		}

	}

private:
	int i, j, k;
	float fthreshold;
	//fthreshold : 比例阈值,只保留满足一定阈值的公共串
	int len1, len, n, up, mx,threshold;
	//mx :	所有串里面,最大的长度
	//up :	字符串之间的分割符
	int *sa, *rank, *height, *cate;
	unsigned int *wa, *wb, *wv, *ws, *a;
	//sa[]:		后缀数组
	//cate[] :  记录某种字符属于那个字符串
	//a[]	:	所有字符串会拼接在一起,字符串与字符串之间的分隔符使用 "up + 字符串id "隔开
	//rank[] :名次数组
	//height[] : 
	char  *flag;//字符串的个数
	
	int allocate;
	int used;
private:
	set<string> pattern_str;
	set<int> pattern_start;
};

#endif