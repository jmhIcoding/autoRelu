#pragma once
#ifndef SUFFIXSEARCH
#define SUFFIXSEARCH
#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <stdlib.h>
using namespace std;

#define maxn (1460 *4)
#define maxPacket (1000)
int cmp(int *r, int a, int b, int l)
//�ַ����ȽϺ���
{
	return r[a] == r[b] && r[a + l] == r[b + l];
}

void da(  int *r,   int *sa, int n, int m,  int *wa,  int *wb,  int *ws,  int *wv)
//�������봮,�������ĺ�׺����
{
	int i, j, p, *x = wa, *y = wb, *t;
	for (i = 0; i<m; i++) ws[i] = 0;
	for (i = 0; i<n; i++) ws[x[i] = r[i]]++;
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

void calheight(  int *r,   int *sa, int n,  int * rank,  int *height)
//�������봮�ͺ�׺����,����rank��height
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
		if (j - i + 2 <= n / 2)
		{
			i = j;
			continue;
		}
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

void print(int tlen,  char *flag,   int *height,   int *cate,   int *sa, int len, int n, int threshold,  int *a )
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
		while (height[i]<tlen && i <= len)
			i++;
		j = i;
		while (height[j] >= tlen && j <= len)
			j++;
		if (j - i + 2 <= n / 2)
		{
			i = j;
			continue;
		}
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
				printf("%c", a[sa[i] + k] - 1);
			printf("\n");
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
		n(0)
	{
		a = (  int *)malloc(sizeof(  int)*maxn);
		cate = (  int *)malloc(sizeof(  int)*maxn);
		allocate = maxn;
		used = 0;	
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
	void feed(char  * payload_str, int length)
		//����µ��غ�����
	{
		len1 = length;
		if (len1 > mx)
		{
			mx = len1;
		}
		while (!((allocate - used- 10) > len1))
			//�ڴ治��,�ȷ����ڴ�
		{
			allocate +=max(maxn,allocate); //���������ڴ�
			int * p_cate = (int *)malloc(sizeof(int)* allocate);
			int * p_a = (int *)malloc(sizeof(int)* allocate);
			memcpy(p_cate, cate, used * sizeof(int));
			memcpy(p_a, a, used * sizeof(int));
			free(a);
			free(cate);
			cate = p_cate;
			a = p_a;
		}
		for (k = 0; k < len1; k++)
		{
			cate[j] = i;
			a[j++] = payload_str[k] + 1;
		}
		cate[j] = -1;
		a[j++] = up + i;

		i++;
		n++;
		used += len1 + 1;
	}
	void calc()
	{
		//���븨���ڴ�
		sa = (  int *)malloc(sizeof(  int)*allocate);
		rank = (  int *)malloc(sizeof(  int)*allocate);
		height = (int *)malloc(sizeof(int)*allocate);
		wa = (  int *)malloc(sizeof(  int)*allocate);
		wb = (  int *)malloc(sizeof(  int)*allocate);
		wv = (  int *)malloc(sizeof(  int)*allocate);
		ws =  (  int *)malloc(sizeof(  int)*allocate);

		flag = (char *)malloc(sizeof(char)* max(n+10,maxPacket));

		//����
		a[--j] = 0;
		len = j;
		threshold = n * fthreshold;
		da(a, sa, len + 1, 300, wa, wb, ws, wv);
		calheight(a, sa, len, rank, height);
		solve();
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
		//printf("%d.....\n", ans);//...
		print(ans,flag,height,cate,sa,len,n,threshold,a);
	}

private:
	int i, j, k;
	float fthreshold;
	//fthreshold : ������ֵ,ֻ��������һ����ֵ�Ĺ�����
	int len1, len, n, up, mx,threshold;
	//mx :	���д�����,���ĳ���
	//up :	�ַ���֮��ķָ��
	int *sa,*rank,*height;
	int *wa, *wb, *wv, *ws, *a, *cate;
	//sa[]:		��׺����
	//cate[] :  ��¼ĳ���ַ������Ǹ��ַ���
	//a[]	:	�����ַ�����ƴ����һ��,�ַ������ַ���֮��ķָ���ʹ�� "up + �ַ���id "����
	//rank[] :��������
	//height[] : 
	char  *flag;//�ַ����ĸ���
	
	int allocate;
	int used;
};

#endif