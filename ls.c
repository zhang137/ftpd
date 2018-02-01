#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include "sysutil.h"
#include "dataprocess.h"

#define MAX(x,y) ((x) < (y) ? (y) : (x))

int max_align(int align,int to_align)
{
    int tmp = to_align;
    int ncount = 0;
    while(tmp > 0)
    {
        tmp /= 10;
        ncount++;
    }

    return MAX(ncount,align);
}


int util_ls(int fd,const char *ptrPath)
{
    struct sysutil_dir *p_Dir;
    struct sysutil_statbuf *statbuf;
    struct sysutil_user   *p_pwd;
    struct sysutil_group  *p_grp;

    const char *ptr_dname;
    double total_size = 0;
    int j = 0,linknum_align = 0,filesize_align = 0;
    char *entries_permission = (char *)sysutil_malloc(sizeof(char) * 11);
    char *p_buf = (char *)sysutil_malloc(256);

    if(access(ptrPath,F_OK))
        die("access");

    p_Dir = sysutil_opendir(ptrPath);
    if(!p_Dir)
    {
        die("opendir");
    }

    while(ptr_dname = sysutil_next_dirent(p_Dir))
    {
        sysutil_stat(ptr_dname,&statbuf);
        filesize_align = max_align(filesize_align,statbuf->st_size);
        linknum_align = max_align(linknum_align,statbuf->st_nlink);
    }
    sysutil_rewinddir(p_Dir);

    while(ptr_dname = sysutil_next_dirent(p_Dir))
    {

        if(!strcmp(ptr_dname,".") || !strcmp(ptr_dname,"..")
           || ptr_dname[0] == '.')
           continue;
        memset(entries_permission,0,11);
        if(!stat(ptr_dname,statbuf))
        {
            memcpy(entries_permission,"----------",10);

            if(S_ISDIR(statbuf->st_mode))
                entries_permission[0] = 'd';
            else if(S_ISLNK(statbuf->st_mode))
                entries_permission[0] = 'l';

            if(statbuf->st_mode & S_IRUSR)
                entries_permission[1] = 'r';

            if(statbuf->st_mode & S_IWUSR)
                entries_permission[2] = 'w';

            if(statbuf->st_mode & S_IXUSR)
                entries_permission[3] = 'x';

            if(statbuf->st_mode & S_IRGRP)
                entries_permission[4] = 'r';

            if(statbuf->st_mode & S_IWGRP)
                entries_permission[5] = 'w';

            if(statbuf->st_mode & S_IXGRP)
                entries_permission[6] = 'x';

            if(statbuf->st_mode & S_IROTH)
                entries_permission[7] = 'r';

            if(statbuf->st_mode & S_IWOTH)
                entries_permission[8] = 'w';

            if(statbuf->st_mode & S_IXOTH)
                entries_permission[9] = 'x';

            p_pwd = sysutil_getpwuid(statbuf->st_uid);
            p_grp = sysutil_getgrgid(statbuf->st_gid);

            char *ptr_time = ctime(&statbuf->st_mtim);
            ptr_time[strlen(ptr_time) - 1] = '\0';

            sysutil_memclr(p_buf,256);
            sprintf(p_buf,"%s %*d %s  %s  %*d  %s  %s\r\n",entries_permission,linknum_align,statbuf->st_nlink,
                    p_pwd->pw_name,p_grp->gr_name,filesize_align,statbuf->st_size ,ptr_time,ptr_dname);
             write_cmd_respond(fd,0,p_buf);
        }
    }
    sysutil_syslog("ls",LOG_INFO | LOG_USER);
    sysutil_free(p_buf);
    sysutil_closedir(p_Dir);
    sysutil_free(entries_permission);

    sysutil_syslog("ls...",LOG_INFO | LOG_USER);
    return 1;
}
