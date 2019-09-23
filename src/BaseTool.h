#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <direct.h>
#include <io.h>
#else
#include <dirent.h>
#include <unistd.h>
#endif
#include <string>
#include <string.h>

#include <vector>

using namespace std;
#ifdef WIN32
vector<string> get_files_from_dir(char * dir,char *filter=NULL)
{
	vector<string> rst;
	_finddata_t file;
	long lf = _findfirst(dir, &file);
	if (lf == -1)
	{
		printf("error (%s,%d):canot read directory:%s\n", __FUNCTION__, __LINE__, dir);
	}
	else
	{
		while (_findnext(lf, &file) == 0)
		{
			if (strcmp(file.name, ".") == 0 || strcmp(file.name, "..") == 0)
				// filter .. and . directory.
			{
				continue;
			}
			if (filter == NULL || strstr(file.name, filter) != NULL)
			{
				rst.push_back(file.name);
			}
		}
	}
	return rst;
}
#else
vector<string> get_files_from_dir(char * basepath,char *filter=NULL)
{
	vector<string> rst;
	DIR *dir=opendir(basepath);
	struct dirent *ptr;
	if (dir==NULL)
	{
		printf("error (%s,%d):canot read directory:%s\n", __FUNCTION__, __LINE__, basepath);
	}
	else
	{
		while ((ptr=readdir(dir))==NULL)
		{
			if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0)
				// filter .. and . directory.
			{
				continue;
			}
			if (filter == NULL || strstr(ptr->d_name, filter) != NULL)
			{
				rst.push_back(ptr->d_name);
			}
		}
	}
	return rst;
}
#endif