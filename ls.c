#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>

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
    DIR *Dir;
    struct stat statbuf;
    struct dirent *tmp;
    struct passwd *pwd;
    struct group  *grp;
    char *entries_permission;
    //char *dir_entries[50];
    int entry_size,j = 0;
    u_int64_t total_size = 0;
    int linknum_align = 0,filesize_align = 0;

    entries_permission = (char *)malloc(sizeof(char) * 11);
    if(!ptrPath || access(ptrPath,F_OK))
        return;

    chdir(ptrPath);

    stat(ptrPath,&statbuf);
    total_size += statbuf.st_size;

    Dir = opendir(ptrPath);
    if(!Dir)
    {
        perror("opendir");
        exit(-1);
    }

    while(tmp = readdir(Dir))
    {
        stat(tmp->d_name,&statbuf);
        total_size += statbuf.st_size;
        filesize_align = max_align(filesize_align,statbuf.st_size);
        linknum_align = max_align(linknum_align,statbuf.st_nlink);
    }

    rewinddir(Dir);
    fprintf(stdout,"total  %llu\n",total_size/1024);
    while(tmp = readdir(Dir))
    {

        if(!strcmp(tmp->d_name,".") || !strcmp(tmp->d_name,"..")
           || tmp->d_name[0] == '.')
           continue;
        memset(entries_permission,0,11);
        if(!stat(tmp->d_name,&statbuf))
        {
            memcpy(entries_permission,"----------",10);

            if(S_ISDIR(statbuf.st_mode))
                entries_permission[0] = 'd';
            else if(S_ISLNK(statbuf.st_mode))
                entries_permission[0] = 'l';

            if(statbuf.st_mode & S_IRUSR)
                entries_permission[1] = 'r';

            if(statbuf.st_mode & S_IWUSR)
                entries_permission[2] = 'w';

            if(statbuf.st_mode & S_IXUSR)
                entries_permission[3] = 'x';

            if(statbuf.st_mode & S_IRGRP)
                entries_permission[4] = 'r';

            if(statbuf.st_mode & S_IWGRP)
                entries_permission[5] = 'w';

            if(statbuf.st_mode & S_IXGRP)
                entries_permission[6] = 'x';

            if(statbuf.st_mode & S_IROTH)
                entries_permission[7] = 'r';

            if(statbuf.st_mode & S_IWOTH)
                entries_permission[8] = 'w';

            if(statbuf.st_mode & S_IXOTH)
                entries_permission[9] = 'x';

            pwd = getpwuid(statbuf.st_uid);
            grp = getgrgid(statbuf.st_gid);

            char *ptr_time = ctime(&statbuf.st_mtim);
            ptr_time[strlen(ptr_time) - 1] = '\0';
            fprintf(stdout,"%s %*d %s  %s  %*d  %s  %s\n",entries_permission,linknum_align,statbuf.st_nlink,
                    pwd->pw_name,grp->gr_name,linknum_align,statbuf.st_size ,ptr_time,tmp->d_name);
        }

    }
    closedir(Dir);
    free(entries_permission);
}
