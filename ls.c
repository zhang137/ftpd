#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <grp.h>
#include <pwd.h>


void util_ls(const char *p_ptrPath)
{
    DIR *Dir;
    struct stat statbuf;
    struct dirent *tmp;
    struct passwd *pwd;
    struct group  *grp;
    char *entries_permission;
    char *dir_entries[20];
    int entry_size,total_size = 0,i = 1,j;

    entries_permission = (char *)malloc(sizeof(char)*11);
    for(j = 0; j < 20; j++){
        dir_entries[j] = (char *)malloc(sizeof(char) * 100);
        memset(dir_entries[j],0,100);
    }
    if(!p_ptrPath)
        return;

    chdir(p_ptrPath);
    Dir = opendir(p_ptrPath);
    if(!Dir)
    {
        perror("opendir");
        exit(-1);
    }

    while(tmp = readdir(Dir))
    {
        if(!strcmp(tmp->d_name,".") || !strcmp(tmp->d_name,".."))
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
            total_size += statbuf.st_size;
            sprintf(dir_entries[i],"%s %lu  %s %s %.2lfkb %s  %s\n",entries_permission,statbuf.st_nlink,
                    pwd->pw_name,grp->gr_name,(float)statbuf.st_size / 1024,ptr_time,tmp->d_name);
            i++;
        }

    }
    sprintf(dir_entries[0],"total  %d\n",total_size);

    for(j = 0; j < i; j++)
        printf("%s",dir_entries[j]);

    for(j = 0; j < 20; j++)
        free(dir_entries[j]);
    closedir(Dir);
    free(entries_permission);
}

