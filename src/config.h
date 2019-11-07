#ifndef __CONFIGH__
#define __CONFIGH__
int min_length_of_frequentstr=4;			//频繁字符串的最小长度
int max_length_of_frequentstr = 32;			//频繁字符串的最大长度
const char * pcap_dir="/home/dk/targets/weixin/";	//数据包目录
float freq_threshold=0.6;						//出现次数最低比例
const char * output_file="./target.log";	//输出结果保存在那个文件中
const bool sort_by_length=false;				//输出结果按照长度排序？ true(按长度排序):false(按出现频次排序);全部都是降序
#endif
