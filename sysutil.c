#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/un.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include "sysutil.h"

int sysutil_retval_is_error(int retval)
{
    return 0;
}


void sysutil_install_null_sighandler(const enum EVSFSysUtilSignal sig)
{

}

void sysutil_install_sighandler(const enum EVSFSysUtilSignal sig,
                                    async_sighandle_t handler,
                                    void* p_private,
                                    int use_alarm)
{

}
void sysutil_install_async_sighandler(const enum EVSFSysUtilSignal sig,
                                          async_sighandle_t handler)
{
}
void sysutil_default_sig(const enum EVSFSysUtilSignal sig)
{
}
void sysutil_install_io_handler(context_io_t handler, void* p_private)
{
}
void sysutil_uninstall_io_handler(void)
{
}
void sysutil_check_pending_actions(
  const enum EVSFSysUtilInterruptContext context, int retval, int fd)
{
}
void sysutil_block_sig(const enum EVSFSysUtilSignal sig)
{
}
void sysutil_unblock_sig(const enum EVSFSysUtilSignal sig)
{
}

/* Alarm setting/clearing utility functions */
void sysutil_set_alarm(const unsigned int trigger_seconds)
{
    alarm(trigger_seconds);
}
void sysutil_clear_alarm(void)
{
    alarm(0);
}

/* Directory related things */
char* sysutil_getcwd(char* p_dest, const unsigned int buf_size)
{
    char *p_retval;
    if(buf_size == 0)
        return p_dest;
    p_retval = getcwd(p_dest,buf_size);
    p_retval[buf_size] = '\0';
    return p_retval;
}
int sysutil_mkdir(const char* p_dirname, const unsigned int mode)
{
    return mkdir(p_dirname,mode);
}
int sysutil_rmdir(const char* p_dirname)
{
    return rmdir(p_dirname);
}
int sysutil_chdir(const char* p_dirname)
{
    return chdir(p_dirname);
}
int sysutil_rename(const char* p_from, const char* p_to)
{
    return rename(p_from,p_to);
}

struct sysutil_dir* sysutil_opendir(const char* p_dirname)
{

    return (struct sysutil_dir*)opendir(p_dirname);
}

void sysutil_closedir(struct sysutil_dir* p_dir)
{
    struct sysutil_dir* pdir = p_dir;
    int ret = closedir(pdir);
    if(ret < 0);
        //die("closedir");
}
const char* sysutil_next_dirent(struct sysutil_dir* p_dir)
{
    struct dirent *tmp = readdir(p_dir);
    if(tmp == NULL) return NULL;
    return tmp->d_name;
}

int sysutil_open_file(const char* p_filename,
                          const enum EVSFSysUtilOpenMode mode)
{
    int fd;
    if(mode & kVSFSysUtilOpenReadOnly) {
        fd = open(p_filename,O_NONBLOCK|O_RDONLY);
    }else if(mode & kVSFSysUtilOpenWriteOnly){
        fd = open(p_filename,O_NONBLOCK|O_WRONLY);
    }else {
        fd = open(p_filename,O_NONBLOCK|O_RDWR);
    }
    return fd;
}
/* Fails if file already exists */
int sysutil_create_file_exclusive(const char* p_filename)
{
    return open(p_filename,O_CREAT|O_EXCL|O_APPEND|O_WRONLY,0666);
}
/* Creates file or appends if already exists */
int sysutil_create_or_open_file_append(const char* p_filename,
                                           unsigned int mode)
{
    return open(p_filename,O_CREAT|O_APPEND|O_WRONLY|O_NONBLOCK,mode);
}
/* Creates or appends */
int sysutil_create_or_open_file(const char* p_filename, unsigned int mode)
{
    return open(p_filename,O_CREAT|O_RDWR|O_NONBLOCK,mode);
}
void sysutil_dupfd2(int old_fd, int new_fd)
{

}
void sysutil_close(int fd)
{
    close(fd);
}

int sysutil_close_failok(int fd)
{
    return 0;
}

int sysutil_unlink(const char* p_dead)
{
    return unlink(p_dead);
}

int sysutil_write_access(const char* p_filename)
{
    return access(p_filename,W_OK);
}

void sysutil_ftruncate(int fd)
{

}

/* Reading and writing */
void sysutil_lseek_to(const int fd, filesize_t seek_pos)
{
    int res;
    if((res = lseek(fd,SEEK_SET,seek_pos))< 0)
    {

    }
}
void sysutil_lseek_end(const int fd)
{
    int res;
    res = lseek(fd,SEEK_END,0);
    if(res < 0)
        ;//die("lseek");
}

filesize_t sysutil_get_file_offset(const int file_fd)
{
    return lseek(file_fd,SEEK_CUR,0);
}
int sysutil_read(const int fd, void* p_buf, const unsigned int size)
{
    ssize_t nread;
    nread = read(fd,p_buf,size);
    if(nread <= 0)
    {
        if(errno == EINTR)
            return 0;
        return -1;
    }
    return nread;
}
int sysutil_write(const int fd, const void* p_buf,const unsigned int size)
{
    ssize_t nwrite;
    nwrite = write(fd,p_buf,size);
    if(nwrite <= 0)
    {
        if(errno == EINTR)
            return 0;
        return -1;
    }

    return nwrite;
}
/* Reading and writing, with handling of interrupted system calls and partial
 * reads/writes. Slightly more usable than the standard UNIX API!
 */
int sysutil_read_loop(const int fd, void* p_buf, unsigned int size)
{
    int ntotal = size;
    int nread = 0,ntmp;
    while(nread < size)
    {
        ntmp = sysutil_read(fd,p_buf+nread,ntotal);
        if(ntmp == 0) {
            continue;
        }
        if(ntmp < 0) {
            return -1;//die("read");
        }
        nread += ntmp;
        ntotal -= ntmp;
    }

    return 0;
}
int sysutil_write_loop(const int fd, const void* p_buf, unsigned int size)
{
    int ntotal = size;
    int nwrite = 0,ntmp;
    while(nwrite < size)
    {
        ntmp = sysutil_write(fd,p_buf+nwrite,ntotal);
        if(ntmp == 0) {
            continue;
        }
        if(ntmp < 0) {
            return -1;
        }
        nwrite += ntmp;
        ntotal -= ntmp;
    }
    return 0;
}


int sysutil_stat(const char* p_name, struct sysutil_statbuf** p_ptr)
{
    struct sysutil_statbuf statbuf;
    if(stat(p_name,&statbuf) < 0)
    {
        return -1;
    }
    *p_ptr = &statbuf;
    return 0;
}
int sysutil_lstat(const char* p_name, struct sysutil_statbuf** p_ptr)
{
    struct sysutil_statbuf statbuf;
    if(lstat(p_name,&statbuf) < 0)
    {

    }
    *p_ptr = &statbuf;
    return 0;
}
void sysutil_fstat(int fd, struct sysutil_statbuf** p_ptr)
{
    struct sysutil_statbuf statbuf;
    if(fstat(fd,&statbuf) < 0)
    {

    }
    *p_ptr = &statbuf;
    return 0;
}
void sysutil_dir_stat(const struct sysutil_dir* p_dir,
                          struct sysutil_statbuf** p_ptr)
{
    struct stat statv;

}
int sysutil_statbuf_is_regfile(const struct sysutil_statbuf* p_stat)
{
    return S_ISREG(p_stat->st_mode);
}
int sysutil_statbuf_is_symlink(const struct sysutil_statbuf* p_stat)
{
    return S_ISLNK(p_stat->st_mode);
}
int sysutil_statbuf_is_socket(const struct sysutil_statbuf* p_stat)
{
    return S_ISSOCK(p_stat->st_mode);
}
int sysutil_statbuf_is_dir(const struct sysutil_statbuf* p_stat)
{
    return S_ISDIR(p_stat->st_mode);
}
filesize_t sysutil_statbuf_get_size(
  const struct sysutil_statbuf* p_stat)
{
    return p_stat->st_size;
}
const char* sysutil_statbuf_get_perms(
  const struct sysutil_statbuf* p_stat)
{
    //p_stat->
    return 0;
}
const char* sysutil_statbuf_get_date(
  const struct sysutil_statbuf* p_stat, int use_localtime, long curr_time)
{

    return 0;
}
const char* sysutil_statbuf_get_numeric_date(
  const struct sysutil_statbuf* p_stat, int use_localtime)
{

    return 0;
}
unsigned int sysutil_statbuf_get_links( const struct sysutil_statbuf* p_stat )
{
    return p_stat->st_nlink;
}
int sysutil_statbuf_get_uid(const struct sysutil_statbuf* p_stat)
{
    return p_stat->st_uid;
}
int sysutil_statbuf_get_gid(const struct sysutil_statbuf* p_stat)
{
    return p_stat->st_gid;
}
int sysutil_statbuf_is_readable_other(
  const struct sysutil_statbuf* p_stat)
{
    return __S_ISTYPE(p_stat->st_mode,S_IROTH);
}


const char* sysutil_statbuf_get_sortkey_mtime(
  const struct sysutil_statbuf* p_stat)
{

    return 0;
}


int sysutil_chmod(const char* p_filename, unsigned int mode)
{
    return chmod(p_filename,mode);
}
void sysutil_fchown(const int fd, const int uid, const int gid)
{
    fchown(fd,uid,gid);
}
void sysutil_fchmod(const int fd, unsigned int mode)
{
    fchmod(fd,mode);
}
int sysutil_readlink(const char* p_filename, char* p_dest,
                         unsigned int bufsiz)
{
    return readlink(p_filename,p_dest,bufsiz);
}
/* Get / unget various locks. Lock gets are blocking. Write locks are
 * exclusive read locks are shared.
 */
int sysutil_lock_file_write(int fd)
{
    struct flock lock;
    lock.l_pid = sysutil_getpid();
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;

    if(fcntl(fd,F_SETLK,lock) < 0)
    {
        ;//die("fcntl");
        return -1;
    }

    return 0;
}
int sysutil_lock_file_read(int fd)
{
    struct flock lock;
    lock.l_pid = sysutil_getpid();
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_type = F_RDLCK;
    lock.l_whence = SEEK_SET;

    if(fcntl(fd,F_SETLK,lock) < 0)
        ;//die("fcntl");
    return 0;
}
void sysutil_unlock_file(int fd)
{

    struct flock lock;
    lock.l_pid = sysutil_getpid();
    lock.l_start = 0;
    lock.l_len = 0;
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;

    if(fcntl(fd,F_SETLK,lock) < 0)
        ;//die("fcntl");
    return 0;
}

void sysutil_memprotect(void* p_addr, unsigned int len,
                            const enum EVSFSysUtilMapPermission perm)
{

}
void sysutil_memunmap(void* p_start, unsigned int length)
{

}

/* Memory allocating/freeing */
void* sysutil_malloc(unsigned int size)
{
    void *ptr;

    if(size == 0 || size > INT_MAX)
        ;//die("malloc zero or size is too big");

    ptr = malloc(size);
    if(ptr == NULL)
        ;//die("malloc error");

    return ptr;
}

void* sysutil_realloc(void* p_ptr, unsigned int size)
{
    void *ptr;

    if(size == 0 || size > INT_MAX)
        ;//die("malloc zero or size is too big");

    ptr = realloc(p_ptr,size);
    if(ptr == NULL)
        ;//die("realloc error");

    return ptr;
}
void sysutil_free(void* p_ptr)
{
    free(p_ptr);
}

/* Process creation/exit/process handling */
unsigned int sysutil_getpid(void)
{
    return getpid();
}
void sysutil_post_fork(void)
{

}
int sysutil_fork(void)
{
    pid_t pid;
    pid = fork();
    if(pid > 0)
    {
        sysutil_exit(-1);
    }
    return 0;
}
int sysutil_fork_failok(void)
{

    return 0;
}
void sysutil_exit(int exit_code)
{
    _exit(exit_code);
}

struct sysutil_wait_retval sysutil_wait(void)
{
    struct sysutil_wait_retval ret;

    //ret.


    return ret;
}
int sysutil_wait_reap_one(void)
{
    int status;
    pid_t pid;
    pid = wait(&status);
    if(pid < 0)
    {

    }
    return pid;
}
int sysutil_wait_get_retval(
  const struct sysutil_wait_retval* p_waitret)
{

    return 0;
}
int sysutil_wait_exited_normally(
  const struct sysutil_wait_retval* p_waitret)
{
    return 0;
}
int sysutil_wait_get_exitcode(
  const struct sysutil_wait_retval* p_waitret)
{
    return 0;
}


/* Various string functions */
unsigned int sysutil_strlen(const char* p_text)
{
    unsigned int len = strlen(p_text);
    if(len > INT_MAX / 8)
    {
        ;//die("string len too large");
    }
    return len;
}
char* sysutil_strdup(const char* p_str)
{
    return 0;
}
void sysutil_memclr(void* p_dest, unsigned int size)
{
    memset(p_dest,0,size);
}
void sysutil_memcpy(void* p_dest, const void* p_src,
                        const unsigned int size)
{
    if(p_dest == p_src)
        return;
    memcpy(p_dest,p_src,size);
}
void sysutil_strcpy(char* p_dest, const char* p_src, unsigned int maxsize)
{
    sysutil_memcpy(p_dest,p_src,maxsize);
}

int sysutil_memcmp(const void* p_src1, const void* p_src2,
                       unsigned int size)
{
    if(size == 0)
        return 0;
    return memcmp(p_src1,p_src2,size);
}
int sysutil_strcmp(const char* p_src1, const char* p_src2)
{
    return strcmp(p_src1,p_src2);
}
int sysutil_atoi(const char* p_str)
{
    return atoi(p_str);
}
filesize_t sysutil_a_to_filesize_t(const char* p_str)
{
    return atoll(p_str);
}
const char* sysutil_ulong_to_str(unsigned long the_ulong)
{
    //itoa()
    return 0;//ultoa(the_long);
}
const char* sysutil_filesize_t_to_str(filesize_t the_filesize)
{
    return 0;//atoul(the_filesize);
}
const char* sysutil_double_to_str(double the_double)
{
    return 0;//atof(the_double);
}
const char* sysutil_uint_to_octal(unsigned int the_uint)
{
    return 0;
}
unsigned int sysutil_octal_to_uint(const char* p_str)
{
    return 0;
}
int sysutil_toupper(int the_char)
{
    return toupper(the_char);
}
int sysutil_isspace(int the_char)
{
    return isspace(the_char);
}
int sysutil_isprint(int the_char)
{
    return isprint(the_char);
}
int sysutil_isalnum(int the_char)
{
    return isalnum(the_char);
}
int sysutil_isdigit(int the_char)
{
    return isdigit(the_char);
}

void sysutil_sockaddr_alloc(struct sysutil_sockaddr** p_sockptr)
{

    struct sysutil_sockaddr *tmp_addr;
    struct sockaddr saddr;
    tmp_addr = (struct sysutil_sockaddr *)sysutil_malloc(sizeof(struct sysutil_sockaddr));
    sysutil_sockaddr_clear(&tmp_addr);
    tmp_addr->u.u_sockaddr = saddr;
    *p_sockptr = tmp_addr;
}
void sysutil_sockaddr_clear(struct sysutil_sockaddr** p_sockptr)
{
    sysutil_memclr(*p_sockptr,sizeof(*p_sockptr));
}
void sysutil_sockaddr_alloc_ipv4(struct sysutil_sockaddr** p_sockptr)
{
    struct sysutil_sockaddr *tmp_addr;
    struct sockaddr_in saddr_in;
    saddr_in.sin_family = AF_INET;
    tmp_addr = (struct sysutil_sockaddr *)sysutil_malloc(sizeof(struct sysutil_sockaddr));
    sysutil_sockaddr_clear(&tmp_addr);
    tmp_addr->u.u_sockaddr_in = saddr_in;
    *p_sockptr = tmp_addr;

}
void sysutil_sockaddr_alloc_ipv6(struct sysutil_sockaddr** p_sockptr)
{
    struct sysutil_sockaddr *tmp_addr;
    struct sockaddr_in6 saddr_in6;
    saddr_in6.sin6_family = AF_INET6;
    tmp_addr = (struct sysutil_sockaddr *)sysutil_malloc(sizeof(struct sysutil_sockaddr));
    sysutil_sockaddr_clear(&tmp_addr);
    tmp_addr->u.u_sockaddr_in6 = saddr_in6;
    *p_sockptr = tmp_addr;
}
void sysutil_sockaddr_clone (struct sysutil_sockaddr** p_sockptr,
                                    const struct sysutil_sockaddr* p_src)
{
    sysutil_memcpy(*p_sockptr,p_src,sizeof(struct sysutil_sockaddr));
}
int sysutil_sockaddr_addr_equal(const struct sysutil_sockaddr* p1,
                                    const struct sysutil_sockaddr* p2)
{
    return sysutil_memcmp(p1,p2,sizeof(struct sysutil_sockaddr));
}
int sysutil_sockaddr_is_ipv6(
  const struct sysutil_sockaddr* p_sockaddr)
{
    return p_sockaddr->u.u_sockaddr_in6.sin6_family == AF_INET6;
}
void sysutil_sockaddr_set_ipv4addr(struct sysutil_sockaddr* p_sockptr,
                                       const unsigned char* p_raw)
{
    sysutil_inet_aton(p_raw,p_sockptr);
}
void sysutil_sockaddr_set_ipv6addr(struct sysutil_sockaddr* p_sockptr,
                                       const unsigned char* p_raw)
{
    sysutil_inet_aton(p_raw,p_sockptr);
}
void sysutil_sockaddr_set_any(struct sysutil_sockaddr* p_sockaddr)
{
    sysutil_inet_aton(INADDR_ANY,p_sockaddr);
}
unsigned short sysutil_sockaddr_get_port(
    const struct sysutil_sockaddr* p_sockptr)
{
    return 0;
}
void sysutil_sockaddr_set_port(struct sysutil_sockaddr* p_sockptr,
                                   unsigned short the_port)
{
    if(p_sockptr->u.u_sockaddr_in.sin_family == AF_INET)
        p_sockptr->u.u_sockaddr_in.sin_port = htons(the_port);
    else if(p_sockptr->u.u_sockaddr_in6.sin6_family == AF_INET6)
        p_sockptr->u.u_sockaddr_in6.sin6_port = htons(the_port);
}
int sysutil_is_port_reserved(unsigned short port)
{
    struct sysutil_sockaddr saddr;
    struct sockaddr_in addr;
    int fd;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    saddr.u.u_sockaddr_in = addr;
    fd = sysutil_get_ipv4_sock();
    if(fd < 0)
        return -1;
    if(sysutil_bind(fd,&saddr) < 0)
        return 1;
    return 0;
}
int sysutil_get_ipsock(const struct sysutil_sockaddr* p_sockaddr)
{
    return 0;
}
unsigned int sysutil_get_ipaddr_size(void)
{

    return 0;
}
void* sysutil_sockaddr_get_raw_addr(
  struct sysutil_sockaddr* p_sockaddr)
  {
      return 0;
}
const void* sysutil_sockaddr_ipv6_v4(
  const struct sysutil_sockaddr* p_sockaddr)
  {
      return NULL;
}
const void* sysutil_sockaddr_ipv4_v6(
  const struct sysutil_sockaddr* p_sockaddr)
{
    return 0;
}

int sysutil_get_ipv4_sock(void)
{
    return socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
}
int sysutil_get_ipv6_sock(void)
{
    return socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);
}

struct sysutil_socketpair_retval
  sysutil_unix_stream_socketpair(void)
{
    struct sysutil_socketpair_retval ret;
    int fd[2],res;
    res = socketpair(AF_UNIX,SOCK_STREAM,0,fd);
    if(res < 0)
    {
        //die("sockpair")
        return ret;
    }
    ret.socket_one = fd[0];
    ret.socket_two = fd[1];
    return ret;
}
int sysutil_bind(int fd, const struct sysutil_sockaddr* p_sockptr)
{
    if(p_sockptr->u.u_sockaddr_in.sin_family == AF_INET)
    {
        if(bind(fd,(struct sockaddr *)&p_sockptr->u.u_sockaddr_in,sizeof(struct sockaddr_in)) < 0)
        {
            return -1;
        }
    }
    else if(p_sockptr->u.u_sockaddr_in6.sin6_family == AF_INET6)
    {
        if(bind(fd,(struct sockaddr *)&p_sockptr->u.u_sockaddr_in,sizeof(struct sockaddr_in6)) < 0)
        {
            return -1;
        }
    }
    return 0;
}
int sysutil_listen(int fd, const unsigned int backlog)
{
    if(listen(fd,backlog) < 0)
        return -1;
    return 0;
}
void sysutil_getsockname(int fd, struct sysutil_sockaddr** p_sockptr)
{
    struct sysutil_sockaddr *ptr = *p_sockptr;
    if(ptr->u.u_sockaddr_in.sin_family == AF_INET)
    {

    }
    else if(ptr->u.u_sockaddr_in6.sin6_family == AF_INET6)
    {

    }
}
void sysutil_getpeername(int fd, struct sysutil_sockaddr** p_sockptr)
{
    struct sysutil_sockaddr *ptr = *p_sockptr;
    if(ptr->u.u_sockaddr_in.sin_family == AF_INET)
    {
        getpeername(fd,(struct sockaddr*)&ptr->u.u_sockaddr_in,sizeof(struct sockaddr_in));
    }
    else if(ptr->u.u_sockaddr_in6.sin6_family == AF_INET6)
    {
        getpeername(fd,(struct sockaddr*)&ptr->u.u_sockaddr_in6,sizeof(struct sockaddr_in6));
    }
}
int sysutil_accept_timeout(int fd, struct sysutil_sockaddr* p_sockaddr,
                               unsigned int wait_seconds)
{
    int clientfd,res;
    struct timeval tv;
    gettimeofday(&tv,NULL);
    clientfd = accept(fd,(struct sockaddr*)&p_sockaddr->u.u_sockaddr_in,sizeof(struct sockaddr));
    if(clientfd < 0)
    {
       if (errno != EAGAIN )
           return -1;
    }else {
        return clientfd;
    }
    tv.tv_sec = wait_seconds - tv.tv_sec;
    tv.tv_usec = 0;
    struct fd_set rfdset;
    struct fd_set wfdset;
    struct fd_set efdset;

    FD_ZERO(&rfdset);
    FD_ZERO(&wfdset);

    FD_SET(clientfd,&rfdset);
    FD_SET(clientfd,&wfdset);

    res = select(clientfd+1,&rfdset,&wfdset,NULL,&tv);
    if(res > 0)
    {
        if(FD_ISSET(clientfd,&rfdset) && ! FD_ISSET(clientfd,&wfdset))
            return clientfd;
        if(FD_ISSET(clientfd,&rfdset) && FD_ISSET(clientfd,&wfdset))
        {
            int error;
            if(!setsockopt(clientfd,SOL_SOCKET,SO_ERROR,&error,sizeof(int)))
            {
                saved_errno = errno;
            }
        }
    }

    FD_CLR(&rfdset);
    FD_CLR(&wfdset);
    return -1;
}
int sysutil_connect_timeout(int fd,
                                const struct sysutil_sockaddr* p_sockaddr,
                                unsigned int wait_seconds)
{
    int res;
    struct timeval tv;
    gettimeofday(&tv,NULL);
    res = connect(fd,(struct sockaddr*)&p_sockaddr->u.u_sockaddr_in,sizeof(struct sockaddr));
    if(res < 0)
    {
       if (errno != EINPROGRESS)
           return -1;
    }else {
        return 0;
    }
    tv.tv_sec = wait_seconds - tv.tv_sec;
    tv.tv_usec = 0;
    struct fd_set rfdset;
    struct fd_set wfdset;
    struct fd_set efdset;

    FD_ZERO(&rfdset);
    FD_ZERO(&wfdset);

    FD_SET(clientfd,&rfdset);
    FD_SET(clientfd,&wfdset);

    res = select(fd+1,&rfdset,&wfdset,NULL,&tv);
    if(res > 0)
    {
        if(FD_ISSET(fd,&rfdset) && ! FD_ISSET(fd,&wfdset))
            return 0;
        if(FD_ISSET(fd,&rfdset) && FD_ISSET(fd,&wfdset))
        {
            int error;
            if(!setsockopt(fd,SOL_SOCKET,SO_ERROR,&error,sizeof(int)))
            {
                saved_errno = errno;
            }
        }
    }

    FD_CLR(&rfdset);
    FD_CLR(&wfdset);
    return -1;
}
void sysutil_dns_resolve(struct sysutil_sockaddr** p_sockptr,
                             const char* p_name)
{

}
/* Option setting on sockets */
void sysutil_activate_keepalive(int fd)
{
    int klive;
    if(setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&klive,sizeof(int)) < 0)
        ;//die("setsockopt");

}
void sysutil_set_iptos_throughput(int fd)
{
    int tos;
    if(setsockopt(fd,SOL_IP,IP_TOS,&tos,sizeof(int)) < 0)
        ;//die("setsockopt");
}
void sysutil_activate_reuseaddr(int fd)
{
    int raddr;
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&raddr,sizeof(int)) < 0)
        ;//die("setsockopt");
}
void sysutil_set_nodelay(int fd)
{
    int nodely;
    if(setsockopt(fd,SOL_SOCKET,TCP_NODELAY,&nodely,sizeof(int)) < 0)

        ;//die("setsockopt");
}
void sysutil_activate_sigurg(int fd)
{

}
void sysutil_activate_oobinline(int fd)
{
    int klive;
    if(setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&klive,sizeof(int)) < 0)
        ;//die("setsockopt");
}
void sysutil_activate_linger(int fd)
{
    int klive;
    if(setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&klive,sizeof(int)) < 0)
        ;//die("setsockopt");
}
void sysutil_deactivate_linger_failok(int fd)
{

}
void sysutil_activate_noblock(int fd)
{

}
void sysutil_deactivate_noblock(int fd)
{

}
/* This does SHUT_RDWR */
void sysutil_shutdown_failok(int fd)
{

}
/* And this does SHUT_RD */
void sysutil_shutdown_read_failok(int fd)
{

}
int sysutil_recv_peek(const int fd, void* p_buf, unsigned int len)
{
    return 0;
}

const char* sysutil_inet_ntop( const struct sysutil_sockaddr* p_sockptr)
{
    const char *ptr_addr;
    if(p_sockptr->u.u_sockaddr_in.sin_family == AF_INET)
    {
        ptr_addr = (const char *)malloc(INET_ADDRSTRLEN*sizeof(char));
        ptr_addr = inet_ntop(AF_INET,&(p_sockptr->u.u_sockaddr_in.sin_addr),ptr_addr,INET_ADDRSTRLEN);
    } else if(p_sockptr->u.u_sockaddr_in6.sin6_family  == AF_INET6 )
    {
        ptr_addr = (const char *)malloc(INET6_ADDRSTRLEN*sizeof(char));
        ptr_addr = inet_ntop(AF_INET6,&(p_sockptr->u.u_sockaddr_in6.sin6_addr),ptr_addr,INET6_ADDRSTRLEN);
    }
    return ptr_addr;
}
const char* sysutil_inet_ntoa(const void* p_raw_addr)
{
    struct sockaddr_in *sock = (struct sockaddr_in *)p_raw_addr;
    return inet_ntoa(sock->sin_addr);
}
int sysutil_inet_aton(
  const char* p_text, struct sysutil_sockaddr* p_addr)
{
    return inet_aton(p_text,&p_sockptr->u.u_sockaddr_in.sin_addr);
}


struct sysutil_user* sysutil_getpwuid(const int uid)
{
    return (struct sysutil_user*)getpwuid(uid);
}
struct sysutil_user* sysutil_getpwnam(const char* p_user)
{
    return (struct sysutil_user*)getpwnam(p_user);
}
const char* sysutil_user_getname(const struct sysutil_user* p_user)
{
    return p_user;
}
const char* sysutil_user_get_homedir(
  const struct sysutil_user* p_user)
{
    return 0;
}
int sysutil_user_getuid(const struct sysutil_user* p_user)
{
    return 0;
}
int sysutil_user_getgid(const struct sysutil_user* p_user)
{
    return 0;
}

struct sysutil_group* sysutil_getgrgid(const int gid)
{
    return NULL;
}
const char* sysutil_group_getname(const struct sysutil_group* p_group)
{
    return NULL;
}

/* More random things */
unsigned int sysutil_getpagesize(void)
{
    return 0;
}
unsigned char sysutil_get_random_byte(void)
{
    return 0;
}
unsigned int sysutil_get_umask(void)
{
    return 0;
}
void sysutil_set_umask(unsigned int umask)
{
}
void sysutil_make_session_leader(void)
{
}
void sysutil_reopen_standard_fds(void)
{
}
void sysutil_tzset(void)
{
}
const char* sysutil_get_current_date(void)
{
    return NULL;
}
void sysutil_qsort(void* p_base, unsigned int num_elem,
                       unsigned int elem_size,
                       int (*p_compar)(const void *, const void *))
{

}

char* sysutil_getenv(const char* p_var)
{
    return NULL;
}

void sysutil_set_exit_func(exitfunc_t exitfunc)
{
}
int sysutil_getuid(void)
{
    return 0;
}

/* Syslogging (bah) */
void sysutil_openlog(int force)
{
}
void sysutil_syslog(const char* p_text, int severe)
{
}
void sysutil_closelog(void)
{
}

/* Credentials handling */
int sysutil_running_as_root(void)
{
    return 0;
}
void sysutil_setuid(const struct sysutil_user* p_user)
{
}
void sysutil_setgid(const struct sysutil_user* p_user)
{
}
void sysutil_setuid_numeric(int uid)
{
}
void sysutil_setgid_numeric(int gid)
{
}
int sysutil_geteuid(void)
{
    return 0;
}
int sysutil_getegid(void)
{
    return 0;
}
void sysutil_seteuid(const struct sysutil_user* p_user)
{
}
void sysutil_setegid(const struct sysutil_user* p_user)
{
}
void sysutil_seteuid_numeric(int uid)
{
}
void sysutil_setegid_numeric(int gid)
{
}
void sysutil_clear_supp_groups(void)
{
}
void sysutil_initgroups(const struct sysutil_user* p_user)
{
}
void sysutil_chroot(const char* p_root_path)
{
}

/* Time handling */
/* Do not call get_time_usec() without calling get_time_sec()
 * first otherwise you will get stale data.
 */
long sysutil_get_time_sec(void)
{
    return 0;
}
long sysutil_get_time_usec(void)
{
    return 0;
}
long sysutil_parse_time(const char* p_text)
{
    return 0;
}
void sysutil_sleep(double seconds)
{
}
int sysutil_setmodtime(const char* p_file, long the_time, int is_localtime)
{
    return 0;
}

void sysutil_set_address_space_limit(unsigned long bytes)
{

}
void sysutil_set_no_fds()
{

}

void sysutil_set_no_procs()
{

}





