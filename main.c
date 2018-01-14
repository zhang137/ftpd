#include <stdio.h>
#include <stdlib.h>
#include "session.h"
#include "twoprocess.h"
#include "sysutil.h"
#include "str.h"
#include <errno.h>

int main()
{
    char *path;


    path = getcwd(path,NULL);

    printf("%s  %d:%s",path,res,strerror(errno));
    return 0;
}
