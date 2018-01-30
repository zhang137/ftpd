#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
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


void util_ls(const char *ptrPath)
{
    struct sysutil_dir *p_Dir;
    struct sysutil_statbuf *statbuf;
    const char *ptr_dname;
    struct sysutil_user *p_pwd;
    struct sysutil_group  *p_grp;
    char *entries_permission;

    int entry_size,j = 0;
    double total_size = 0;
    int linknum_align = 0,filesize_align = 0;

    entries_permission = (char *)sysutil_malloc(sizeof(char) * 11);
    if(!ptrPath || access(ptrPath,F_OK))
        return;

    sysutil_chdir(ptrPath);

    sysutil_stat(ptrPath,&statbuf);
    total_size += statbuf->st_size;

    p_Dir = sysutil_opendir(ptrPath);
    if(!p_Dir)
    {
        perror("opendir");
        exit(-1);
    }
    char *p_buf = (char *)sysutil_malloc(1024);
    sysutil_memclr(p_buf,1024);

    while(ptr_dname = sysutil_next_dirent(p_Dir))
    {
        sysutil_stat(ptr_dname,&statbuf);
        total_size += statbuf->st_size;
        filesize_align = max_align(filesize_align,statbuf->st_size);
        linknum_align = max_align(linknum_align,statbuf->st_nlink);
    }

    sysutil_rewinddir(p_Dir);
    if(total_size > 1024)
        fprintf(stdout,"total  %uk\n",(uint32_t)(total_size/1024));
    else
        fprintf(stdout,"total  %llu\n",total_size);

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
            fprintf(p_buf,"%s %*d %s  %s  %*d  %s  %s\n",entries_permission,linknum_align,statbuf->st_nlink,
                    p_pwd->pw_name,p_grp->gr_name,filesize_align,statbuf->st_size ,ptr_time,ptr_dname);

            write_cmd_respond(FTPD_CMDWRIO,-1,p_buf);
        }

    }
    sysutil_closedir(p_Dir);
    free(entries_permission);
}
