#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <utime.h>
#include <sys/un.h>
#include <syslog.h>
#include <string.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#include "commoncode.h"
#include "sysutil.h"
#include "str.h"


/* Private variables to this file */
/* Current umask() */
static unsigned int s_current_umask;
/* Cached time */
static struct timeval s_current_time;
/* Current pid */
static int s_current_pid = -1;
/* Exit function */
static exitfunc_t s_exit_func;
/* Difference in timezone from GMT in seconds */
static long s_timezone;

/* Our internal signal handling implementation details */
static struct sysutil_sig_details
{
    sighandle_t sync_sig_handler;
    void* p_private;
    volatile sig_atomic_t pending;
    int running;
    int use_alarm;
} s_sig_details[NSIG];


static context_io_t s_io_handler;
static void* s_p_io_handler_private;
static int s_io_handler_running;

static void sysutil_set_sighandler(int sig, void (*p_handlefunc)(int));
static void sysutil_common_sighandler(int signum);

struct sysutil_sockaddr
{
    union
    {
        struct sockaddr u_sockaddr;
        struct sockaddr_in u_sockaddr_in;
        struct sockaddr_in6 u_sockaddr_in6;
    } u;
};


void
bug(const char* p_text)
{
  /* Rats. Try and write the reason to the network for diagnostics */
  sysutil_activate_noblock(FTPD_CMDWRIO);
  (void) sysutil_write_loop(FTPD_CMDWRIO, "500 OOPS: ", 10);
  (void) sysutil_write_loop(FTPD_CMDWRIO, p_text,
                                sysutil_strlen(p_text));
  (void) sysutil_write_loop(FTPD_CMDWRIO, "\r\n", 2);
  sysutil_exit(2);
}

void die(const char *exit_str)
{
    sysutil_syslog(exit_str,LOG_INFO | LOG_USER);
#ifdef DIE_DEBUG
  bug(p_text);
#endif
    sysutil_exit(EXIT_FAILURE);
}

int sysutil_retval_is_error(int retval)
{
    if(retval < 0)
        return 1;
    return 0;
}

void sysutil_die_follow_parent()
{
    int retval = 0;
    retval = prctl(PR_SET_PDEATHSIG,SIGTERM,0,0,0);
    if(retval < 0)
    {
        die("die with PR_SET_PDEATHSIG");
    }
}

void headle_exit(int sig)
{
    if(sysutil_wait_reap_one())
        sysutil_exit(0);
}

int sysutil_switch_signo_internal(const enum EVSFSysUtilSignal sig)
{
    int signo;
    switch(sig)
    {
    case kVSFSysUtilSigALRM:
        signo = SIGALRM;
        break;
    case kVSFSysUtilSigTERM:
        signo = SIGTERM;
        break;
    case kVSFSysUtilSigCHLD:
        signo = SIGCHLD;
        break;
    case kVSFSysUtilSigPIPE:
        signo = SIGPIPE;
        break;
    case kVSFSysUtilSigURG:
        signo = SIGURG;
        break;
    case kVSFSysUtilSigHUP:
        signo = SIGHUP;
    default:
        bug("unknowed signal no");
    };

    if(signo < 1 || signo > 64)
    {
        bug("signo is overrange");
    }

    return signo;
}


void sysutil_install_null_sighandler(const enum EVSFSysUtilSignal sig)
{
    int signo;
    int retval;
    struct sigaction saction;
    sigemptyset(&saction.sa_mask);

    signo = sysutil_switch_signo_internal(sig);
    saction.sa_flags = 0;
    saction.sa_handler = SIG_IGN;

    retval = sigaction(signo,&saction,NULL);
    if(retval < 0)
    {
        die("sigaction");
    }

}

void sysutil_install_sighandler(const enum EVSFSysUtilSignal sig,
                                async_sighandle_t handler,
                                void* p_private,
                                int use_alarm)
{

    int signo;
    int retval;
    struct sigaction saction;
    sigemptyset(&saction.sa_mask);

    signo = sysutil_switch_signo_internal(sig);
    saction.sa_flags = 0;
    saction.sa_handler = SIG_IGN;

    retval = sigaction(signo,&saction,NULL);
    if(retval < 0)
    {
        die("sigaction");
    }
}

//static struct sysutil_sig_details
//{
//  sighandle_t sync_sig_handler;
//  void* p_private;
//  volatile sig_atomic_t pending;
//  int running;
//  int use_alarm;
//} s_sig_details[NSIG];

void
sysutil_install_async_sighandler(const enum EVSFSysUtilSignal sig,
                                 async_sighandle_t handler)
{
    int signo;
    signo = sysutil_switch_signo_internal(sig);
    s_sig_details[signo].sync_sig_handler = NULL;
    s_sig_details[signo].p_private = NULL;
    sysutil_block_sig(sig);
    sysutil_set_sighandler(signo,handler);
}

static void
sysutil_set_sighandler(int sig, void (*p_handlefunc)(int))
{
    int retval;
    struct sigaction sigact;

    sysutil_memclr(&sigact, sizeof(sigact));
    sigact.sa_handler = p_handlefunc;

    retval = sigemptyset(&sigact.sa_mask);
    if (retval != 0)
    {
        die("sigemptyset");
    }

    retval = sigaddset(&sigact.sa_mask,sig);
    if (retval != 0)
    {
        die("sigaddset");
    }

    retval = sigaction(sig, &sigact, NULL);
    if (retval != 0)
    {
        die("sigaction");
    }
}

void
sysutil_default_sig(const enum EVSFSysUtilSignal sig)
{

}

void
sysutil_install_io_handler(context_io_t handler, void* p_private)
{
    if (s_io_handler != NULL)
    {
        bug("double register of i/o handler");
    }
    s_io_handler = handler;
    s_p_io_handler_private = p_private;
}

void
sysutil_uninstall_io_handler(void)
{
    if (s_io_handler == NULL)
    {
        bug("no i/o handler to unregister!");
    }
    s_io_handler = NULL;
    s_p_io_handler_private = NULL;
}

static void
sysutil_common_sighandler(int signum)
{
    if (signum < 0 || signum >= NSIG)
    {
        /* "cannot happen" */
        return;
    }
    if (s_sig_details[signum].sync_sig_handler)
    {
        s_sig_details[signum].pending = 1;

        if (s_sig_details[signum].use_alarm)
        {
            alarm(1);
        }
    }
}


void
sysutil_check_pending_actions(const enum EVSFSysUtilInterruptContext context,
                              int retval, int fd)
{
    unsigned int i;
    /* Check the i/o handler before the signal handlers */
    if (s_io_handler && !s_io_handler_running && context == kVSFSysUtilIO)
    {
        s_io_handler_running = 1;
        (*s_io_handler)(retval, fd, s_p_io_handler_private);
        s_io_handler_running = 0;
    }
    for (i=0; i < NSIG; ++i)
    {
        if (s_sig_details[i].pending && !s_sig_details[i].running)
        {
            s_sig_details[i].running = 1;
            if (s_sig_details[i].use_alarm)
            {
                alarm(0);
            }
            if (s_sig_details[i].sync_sig_handler)
            {
                s_sig_details[i].pending = 0;
                (*(s_sig_details[i].sync_sig_handler))(s_sig_details[i].p_private);
            }
            s_sig_details[i].running = 0;
        }
    }
}

void sysutil_block_sig(const enum EVSFSysUtilSignal sig)
{
    int signo;
    int retval;
    sigset_t sigset;
    signo = sysutil_switch_signo_internal(sig);

    if(sigemptyset(&sigset) < 0)
    {
        die("sigemptyset");
    }

    if(sigaddset(&sigset,signo) < 0)
    {
        die("sigaddset");
    }

    if(sigprocmask(SIG_BLOCK,&sigset,NULL) < 0)
    {
        die("sigprocmask");
    }
}
void sysutil_unblock_sig(const enum EVSFSysUtilSignal sig)
{
    int signo;
    int retval;
    sigset_t sigset;
    signo = sysutil_switch_signo_internal(sig);

    if(sigemptyset(&sigset) < 0)
    {
        die("sigemptyset");
    }

    if(sigaddset(&sigset,signo) < 0)
    {
        die("sigaddset");
    }

    if(sigprocmask(SIG_UNBLOCK,&sigset,NULL) < 0)
    {
        die("sigprocmask");
    }

}

/* Alarm setting/clearing utility functions */
void sysutil_set_alarm(const unsigned int trigger_seconds)
{
    alarm(trigger_seconds);
}
void sysutil_clear_alarm(void)
{
    sysutil_set_alarm(0);
}

/* Directory related things */
char* sysutil_getcwd(char* p_dest, const unsigned int buf_size)
{
    char *p_retval;
    p_retval = getcwd(p_dest,buf_size);

    return p_retval;
}
int sysutil_mkdir(const char* p_dirname, const unsigned int mode)
{
    int retval;
    retval = mkdir(p_dirname,mode);
    return retval;
}
int sysutil_rmdir(const char* p_dirname)
{
    int retval;
    retval = rmdir(p_dirname);
    return retval;
}
int sysutil_chdir(const char* p_dirname)
{
    return chdir(p_dirname);
}
int sysutil_rename(const char* p_from, const char* p_to)
{
    int retval;
    retval = rename(p_from,p_to);
    if(retval < 0)
        die("rename");
    return retval;
}

struct sysutil_dir* sysutil_opendir(const char* p_dirname)
{
    return (struct sysutil_dir*)opendir(p_dirname);
}

void sysutil_closedir(struct sysutil_dir* p_dir)
{
    int ret = closedir(p_dir);
    if(ret < 0)
        die("closedir");
}

void sysutil_rewinddir(struct sysutil_dir *p_dir)
{
    rewinddir(p_dir);
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
    int retval = 0;

    switch(mode)
    {
    case kVSFSysUtilOpenReadOnly:
        retval = open(p_filename,O_NONBLOCK|O_RDONLY);
        break;
    case kVSFSysUtilOpenWriteOnly:
        retval = open(p_filename,O_NONBLOCK|O_WRONLY);
        break;
    case kVSFSysUtilOpenReadWrite:
        retval = open(p_filename,O_NONBLOCK|O_RDWR);
        break;
    };

    return retval;
}
/* Fails if file already exists */
int sysutil_create_file_exclusive(const char* p_filename)
{
    return open(p_filename,O_CREAT|O_EXCL|O_APPEND|O_WRONLY);
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
    return open(p_filename,O_CREAT|O_RDWR|O_TRUNC|O_NONBLOCK,mode);
}

void sysutil_dupfd2(int old_fd, int new_fd)
{
    int retval;
    retval = dup2(old_fd,new_fd);
    if(retval < 0)
    {
        die("dup2");
    }
}
void sysutil_close(int fd)
{
    int res;
    res = sysutil_close_failok(fd);
    if(res < 0)
    {
        die("close");
    }
}

int sysutil_close_failok(int fd)
{
    int retval;
    while((retval = close(fd)) < 0)
    {
        if(errno == EINTR)
            continue;
    }
    return retval;
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
        die("lseek");
    }
}
void sysutil_lseek_end(const int fd)
{
    int res;
    res = lseek(fd,SEEK_END,0);
    if(res < 0)
    {
        die("lseek");
    }
}

filesize_t sysutil_get_file_offset(const int file_fd)
{
    return lseek(file_fd,SEEK_CUR,0);
}
int sysutil_read(const int fd, void* p_buf, const unsigned int size)
{
    ssize_t nread;
    int saved_errno;
    while((nread = read(fd,p_buf,size)) < 0)
    {
        if(errno == EINTR || errno == EWOULDBLOCK)
            continue;
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
        if(errno == EINTR || errno == EWOULDBLOCK)
            return 0;
        return -1;
    }
    return nwrite;
}

int sysutil_read_loop(const int fd, void* p_buf, unsigned int size)
{
    int ntotal = size;
    int nread = 0,ntmp;
    while(nread < size)
    {
        ntmp = sysutil_read(fd,p_buf+nread,ntotal);
        if(ntmp <= 0)
        {
            return ntmp;
        }
        nread += ntmp;
        ntotal -= ntmp;
    }

    return nread;
}
int sysutil_write_loop(const int fd, const void* p_buf, unsigned int size)
{
    int ntotal = size;
    int nwrite = 0,ntmp;
    while(nwrite < size)
    {
        ntmp = sysutil_write(fd,p_buf+nwrite,ntotal);
        if(ntmp == 0)
        {
            continue;
        }
        if(ntmp < 0)
        {
            return -1;
        }
        nwrite += ntmp;
        ntotal -= ntmp;
    }
    return 0;
}

int sysutil_stat(const char* p_name, struct sysutil_statbuf** p_ptr)
{
    *p_ptr = (struct sysutil_statbuf*)sysutil_malloc(sizeof(**p_ptr));
    if(stat(p_name,*p_ptr) < 0)
    {
        sysutil_free(*p_ptr);
        return -1;
    }
    return 0;
}

int sysutil_lstat(const char* p_name, struct sysutil_statbuf** p_ptr)
{
    *p_ptr = sysutil_malloc(sizeof(**p_ptr));
    if(lstat(p_name,*p_ptr) < 0)
    {
        return -1;
    }
    return 0;
}
void sysutil_fstat(int fd, struct sysutil_statbuf** p_ptr)
{
    *p_ptr = sysutil_malloc(sizeof(**p_ptr));
    if(fstat(fd,*p_ptr) < 0)
    {
        return -1;
    }
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
    {
        die("malloc error");
    }

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
    if(p_ptr != NULL)
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
    if(pid < 0)
    {
        die("fork");
    }
    return pid;
}
int sysutil_fork_failok(void)
{
    pid_t pid;
    pid = sysutil_fork();
    if(!pid)
    {
        sysutil_post_fork();
    }
    return pid;
}
void sysutil_exit(int exit_code)
{
    _exit(exit_code);
}

struct sysutil_wait_retval sysutil_wait(void)
{
    int status;
    pid_t pid;
    struct sysutil_wait_retval ret;

    pid = waitpid(-1,&status,WNOHANG);
    if(pid < 0)
    {
        die("waitpid");
    }

    ret.exit_status = status;
    ret.syscall_retval = pid;

    return ret;
}
int sysutil_wait_reap_one(void)
{
    pid_t pid = 0;
    struct sysutil_wait_retval retval;

    retval = sysutil_wait();
    if(pid = sysutil_wait_get_retval(&retval))
    {
        if(!sysutil_wait_exited_normally(&retval))
            sysutil_exit(-1);
    }

    return pid;
}
int sysutil_wait_get_retval(
    const struct sysutil_wait_retval* p_waitret)
{
    return p_waitret->syscall_retval;
}
int sysutil_wait_exited_normally(const struct sysutil_wait_retval* p_waitret)
{
    return WIFEXITED(sysutil_wait_get_exitcode(p_waitret));
}
int sysutil_wait_get_exitcode(const struct sysutil_wait_retval* p_waitret)
{
    return p_waitret->exit_status;
}

/* Various string functions */
unsigned int sysutil_strlen(const char* p_text)
{
    unsigned int len = strlen(p_text);
    if(len > INT_MAX / 8)
    {
        die("string len too large");
    }
    return len;
}
char* sysutil_strdup(const char* p_str)
{
    if(p_str == NULL) return NULL;

    return strdup(p_str);
}
void sysutil_memclr(void* p_dest, unsigned int size)
{
    if(!size || !p_dest) return;

    memset(p_dest,'\0',size);
}
void sysutil_memcpy(void* p_dest, const void* p_src,
                    const unsigned int size)
{
    if(p_dest == p_src || !size)
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
    sysutil_sockaddr_clear(p_sockptr);
    *p_sockptr = (struct sysutil_sockaddr *)sysutil_malloc(sizeof(**p_sockptr));
    sysutil_memclr(*p_sockptr,sizeof(**p_sockptr));
}
void sysutil_sockaddr_clear(struct sysutil_sockaddr** p_sockptr)
{
    if(*p_sockptr != NULL)
    {
        sysutil_free(*p_sockptr);
        *p_sockptr = NULL;
    }
}
void sysutil_sockaddr_alloc_ipv4(struct sysutil_sockaddr** p_sockptr)
{
    sysutil_sockaddr_alloc(p_sockptr);
    (*p_sockptr)->u.u_sockaddr.sa_family = AF_INET;
}
void sysutil_sockaddr_alloc_ipv6(struct sysutil_sockaddr** p_sockptr)
{
    sysutil_sockaddr_alloc(p_sockptr);
    (*p_sockptr)->u.u_sockaddr.sa_family = AF_INET6;
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
void sysutil_sockaddr_set_any(struct sysutil_sockaddr* p_sockptr)
{
    struct sockaddr *p_sockaddr = &p_sockptr->u.u_sockaddr;
    if(p_sockaddr->sa_family  == AF_INET)
    {
        p_sockptr->u.u_sockaddr_in.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else if(p_sockaddr->sa_family  == AF_INET6)
    {
        inet_pton(AF_INET6,&p_sockptr->u.u_sockaddr_in6.sin6_addr,htonl(INADDR_ANY));
    }

}
unsigned short sysutil_sockaddr_get_port (const struct
        sysutil_sockaddr* p_sockptr)
{
    unsigned short port;
    struct sockaddr *p_sockaddr = &p_sockptr->u.u_sockaddr;

    if(p_sockaddr->sa_family  == AF_INET)
    {
        port = ntohs(p_sockptr->u.u_sockaddr_in.sin_port);
    }
    else if(p_sockaddr->sa_family  == AF_INET6)
    {
        port = ntohs(p_sockptr->u.u_sockaddr_in6.sin6_port);
    }

    return port;
}
void sysutil_sockaddr_set_port(struct sysutil_sockaddr* p_sockptr,
                               unsigned short the_port)
{
    struct sockaddr *p_sockaddr = &p_sockptr->u.u_sockaddr;
    if(p_sockaddr->sa_family == AF_INET)
    {
        p_sockptr->u.u_sockaddr_in.sin_port = htons(the_port);
    }
    else if(p_sockaddr->sa_family == AF_INET6)
    {
        p_sockptr->u.u_sockaddr_in6.sin6_port = htons(the_port);
    }

}
int sysutil_is_port_reserved(unsigned short port)
{
    int retval = 0;
    int saved_errno;
    struct sysutil_sockaddr *p_addr = NULL;

    int sockfd = sysutil_get_ipv4_sock();
    sysutil_sockaddr_alloc_ipv4(&p_addr);
    sysutil_sockaddr_set_any(p_addr);
    sysutil_sockaddr_set_port(p_addr,port);

    if(sysutil_bind(sockfd,p_addr))
    {
        saved_errno = errno;
        if(errno & EADDRINUSE)
            retval = 1;
        else
            die("port reserved");
    }

    sysutil_sockaddr_clear(&p_addr);
    sysutil_close(sockfd);
    return retval;
}
int sysutil_get_ipsock(const struct sysutil_sockaddr* p_sockaddr)
{
    return 0;
}
unsigned int sysutil_get_ipaddr_size(void)
{

    return INET_ADDRSTRLEN;
}
void* sysutil_sockaddr_get_raw_addr(struct sysutil_sockaddr* p_sockaddr)
{
    return sysutil_inet_ntop(p_sockaddr);
}
const void* sysutil_sockaddr_ipv6_v4(const struct sysutil_sockaddr* p_sockaddr)
{

    return NULL;
}
const void* sysutil_sockaddr_ipv4_v6( const struct sysutil_sockaddr* p_sockaddr)
{

    return 0;
}

int sysutil_get_ipv4_sock(void)
{
    int fd;
    if((fd = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0)
    {
        sysutil_syslog("set socket",LOG_ERR);
        sysutil_exit(EXIT_FAILURE);
    }
    return fd;
}
int sysutil_get_ipv6_sock(void)
{
    //return socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);
}

struct sysutil_socketpair_retval
sysutil_unix_stream_socketpair(void)
{
    struct sysutil_socketpair_retval ret;
    int fd[2],res;
    res = socketpair(AF_UNIX,SOCK_STREAM,0,fd);
    if(res < 0)
    {
        //die("sockpair");
    }
    ret.socket_one = fd[0];
    ret.socket_two = fd[1];
    return ret;
}
int sysutil_bind(int fd, const struct sysutil_sockaddr* p_sockptr)
{
    int retval = 0;
    socklen_t socklen;
    const struct sockaddr *p_sockaddr = &p_sockptr->u.u_sockaddr;
    if(p_sockaddr->sa_family == AF_INET)
    {
        socklen = sizeof(struct sockaddr_in);
    }
    else if(p_sockaddr->sa_family  == AF_INET6)
    {
        socklen = sizeof(struct sockaddr_in6);
    }

    if(bind(fd,p_sockaddr,socklen) < 0)
    {
        if(errno  == EADDRINUSE)
        {
            retval = 1;
        }
        else
        {
            die("bind");
        }
    }
    return retval;
}
int sysutil_listen(int fd, const unsigned int backlog)
{
    int retval = 0;
    if(listen(fd,backlog) < 0)
    {
        retval =  -1;
    }
    return retval;
}
void sysutil_getsockname(int fd, struct sysutil_sockaddr** p_sockptr)
{
    socklen_t sock_len = sizeof(**p_sockptr);
    if(getsockname(fd,&((*p_sockptr)->u.u_sockaddr), &sock_len) < 0)
        die("getsockname");

}
void sysutil_getpeername(int fd, struct sysutil_sockaddr** p_sockptr)
{
    const struct sockaddr *p_sockaddr = &(*p_sockptr)->u.u_sockaddr;
    if(p_sockaddr->sa_family == AF_INET)
    {
        getpeername(fd,(struct sockaddr*)&(*p_sockptr)->u.u_sockaddr_in,sizeof(struct sockaddr_in));
    }
    else if(p_sockaddr->sa_family  == AF_INET6)
    {
        getpeername(fd,(struct sockaddr*)&(*p_sockptr)->u.u_sockaddr_in6,sizeof(struct sockaddr_in6));
    }
}
int sysutil_accept_timeout(int fd, struct sysutil_sockaddr* p_sockaddr,
                           unsigned int wait_seconds)
{
    struct sysutil_sockaddr remote_addr;
    int retval,saved_errno;
    struct timeval tv;
    fd_set rfdset;
    socklen_t socklen = sizeof(remote_addr);

    if(wait_seconds > 0)
    {
        tv.tv_sec = wait_seconds;
        tv.tv_usec = 0;
        FD_ZERO(&rfdset);
        FD_SET(fd,&rfdset);

        do
        {
            retval = select(fd+1,&rfdset,NULL,NULL,&tv);
            saved_errno = errno;
        }
        while(retval < 0 && saved_errno == EINTR);

        if(retval <= 0)
        {
            if(retval == 0)
                errno = EAGAIN;
            return -1;
        }
    }
    retval = accept(fd, &(remote_addr.u.u_sockaddr), &socklen);
    if (retval < 0)
    {
        return retval;
    }

    if(remote_addr.u.u_sockaddr.sa_family != AF_INET &&
            remote_addr.u.u_sockaddr.sa_family != AF_INET6)
    {
        die("can only support ipv4 and ipv6 currently");
    }
    if (p_sockaddr)
    {
        if (remote_addr.u.u_sockaddr.sa_family == AF_INET)
        {
            sysutil_memclr(&remote_addr.u.u_sockaddr_in.sin_zero,
                           sizeof(remote_addr.u.u_sockaddr_in.sin_zero));
            sysutil_memcpy(p_sockaddr, &remote_addr.u.u_sockaddr_in,
                           sizeof(remote_addr.u.u_sockaddr_in));
        }
        else
        {
            sysutil_memcpy(p_sockaddr, &remote_addr.u.u_sockaddr_in6,
                           sizeof(remote_addr.u.u_sockaddr_in6));
        }
    }
    return retval;
}

int sysutil_connect_timeout(int fd,
                            const struct sysutil_sockaddr* p_sockaddr,
                            unsigned int wait_seconds)
{
    int retval,save_errno;
    struct timeval tv;
    fd_set wfdset;

    if(wait_seconds > 0)
        sysutil_activate_noblock(fd);

    retval = connect(fd,&p_sockaddr->u.u_sockaddr,sizeof(*p_sockaddr));
    if((errno == EINPROGRESS) && retval < 0)
    {
        sysutil_syslog("inprocessing ",LOG_INFO | LOG_USER);

        tv.tv_sec = wait_seconds;
        tv.tv_usec = 0;

        FD_ZERO(&wfdset);
        FD_SET(fd,&wfdset);

        do
        {
            retval = select(fd+1,NULL,&wfdset,NULL,&tv);
            save_errno = errno;
        }
        while(retval < 0 && save_errno == EINTR);

        if(retval <= 0)
        {
            if(retval == 0)
                errno = EAGAIN;
            retval = -1;
        }
        else
        {
            socklen_t socklen = sizeof(int);
            int socketopt = getsockopt(fd,SOL_SOCKET,SO_ERROR,&retval,&socklen);
            if(socketopt != 0)
            {
                die("getsockopt");
            }
            if(retval != 0)
            {
                errno = retval;
                retval = -1;
            }
        }
    }

    if(wait_seconds)
        sysutil_deactivate_noblock(fd);

    return -1;
}
void sysutil_dns_resolve(struct sysutil_sockaddr** p_sockptr,
                         const char* p_name)
{
    int i;
    char *ip = NULL;
    struct hostent *hent = gethostent();
    hent = gethostbyname(p_name);

    for(i = 0; hent->h_addr_list[i]; i++)
    {
        if(hent->h_addrtype = AF_INET)
        {
            ip = sysutil_inet_ntoa(hent->h_addr_list[i]);
            sysutil_sockaddr_alloc_ipv4(p_sockptr);
            sysutil_sockaddr_set_ipv4addr(*p_sockptr,ip);
        }
        else if(hent->h_addrtype = AF_INET6)
        {
            ip = sysutil_inet_ntoa(hent->h_addr_list[i]);
            sysutil_sockaddr_alloc_ipv6(p_sockptr);
            sysutil_sockaddr_set_ipv6addr(*p_sockptr,ip);
        }
        break;
    }
}
/* Option setting on sockets */
void sysutil_activate_keepalive(int fd)
{
    int klive;
    if(setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,&klive,sizeof(int)) < 0)
    {
        die("KEEPALIVE");
    }
}
void sysutil_set_iptos_throughput(int fd)
{
    unsigned char tos  = IPTOS_THROUGHPUT;
    if(setsockopt(fd,SOL_IP,IP_TOS,&tos,sizeof(unsigned char)) < 0)
    {
        die("IPTOS");
    }
}
void sysutil_activate_reuseaddr(int fd)
{
    int raddr;
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&raddr,sizeof(int)) < 0)
    {
        die("reuseaddr");
    }

}
void sysutil_set_nodelay(int fd)
{
    int nodelay;
    if(setsockopt(fd,SOL_TCP,TCP_NODELAY,&nodelay,sizeof(int)) < 0)
    {
        die("nodelay");
    }

}
void sysutil_activate_sigurg(int fd)
{

}
void sysutil_activate_oobinline(int fd)
{
    int obbline;
    if(setsockopt(fd,SOL_SOCKET,SO_OOBINLINE,&obbline,sizeof(int)) < 0)
    {
        die("obbline");
    }
}
void sysutil_activate_linger(int fd)
{
    struct linger st_linger;
    st_linger.l_onoff = 1;
    st_linger.l_linger = 0;
    if(setsockopt(fd,SOL_SOCKET,SO_LINGER,&st_linger,sizeof(st_linger)) < 0)
    {
        die("set linger");
    }
}
void sysutil_deactivate_linger_failok(int fd)
{
    struct linger st_linger;
    st_linger.l_onoff = 0;
    st_linger.l_linger = 0;
    if(setsockopt(fd,SOL_SOCKET,SO_LINGER,&st_linger,sizeof(st_linger)) < 0)
    {
        die("del linger");
    }
}
void sysutil_activate_noblock(int fd)
{
    int flags;
    if((flags = fcntl(fd,F_GETFD,0)) < 0 ||
            fcntl(fd , F_SETFD, flags | O_NONBLOCK) < 0)
    {
        die("fcntl noblock");
    }

}
void sysutil_deactivate_noblock(int fd)
{
    int flags;
    if((flags = fcntl(fd,F_GETFD,0)) < 0 ||
            fcntl(fd , F_SETFD, flags | ~O_NONBLOCK) < 0)
    {
        die("fcntl block");
    }
}
/* This does SHUT_RDWR */
void sysutil_shutdown_failok(int fd)
{
    shutdown(fd,SHUT_RDWR);
}
/* And this does SHUT_RD */
void sysutil_shutdown_read_failok(int fd)
{
    shutdown(fd,SHUT_RD);
}
int sysutil_recv_peek(const int fd, void* p_buf, unsigned int len)
{
    return recv(fd,p_buf,len,MSG_PEEK);
}

const char* sysutil_inet_ntop( const struct sysutil_sockaddr* p_sockptr)
{
    const char *ptr_addr;
    if(p_sockptr->u.u_sockaddr_in.sin_family == AF_INET)
    {
        ptr_addr = (const char *)malloc(INET_ADDRSTRLEN*sizeof(char));
        ptr_addr = inet_ntop(AF_INET,&(p_sockptr->u.u_sockaddr_in.sin_addr),ptr_addr,INET_ADDRSTRLEN);
    }
    else if(p_sockptr->u.u_sockaddr_in6.sin6_family  == AF_INET6 )
    {
        ptr_addr = (const char *)malloc(INET6_ADDRSTRLEN*sizeof(char));
        ptr_addr = inet_ntop(AF_INET6,&(p_sockptr->u.u_sockaddr_in6.sin6_addr),ptr_addr,INET6_ADDRSTRLEN);
    }
    return ptr_addr;
}
const char* sysutil_inet_ntoa(const void* p_raw_addr)
{
    return inet_ntoa(*(struct in_addr *)(p_raw_addr));
}

int sysutil_inet_aton(
    const char* p_text, struct sysutil_sockaddr* p_addr)
{
    return inet_aton(p_text,&p_addr->u.u_sockaddr_in.sin_addr);
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
    return p_user->pw_name;
}
const char* sysutil_user_get_homedir(
    const struct sysutil_user* p_user)
{
    return p_user->pw_dir;
}
int sysutil_user_getuid(const struct sysutil_user* p_user)
{
    return p_user->pw_uid;
}
int sysutil_user_getgid(const struct sysutil_user* p_user)
{
    return p_user->pw_gid;
}

struct sysutil_group* sysutil_getgrgid(const int gid)
{
    return getgrgid(gid);
}
const char* sysutil_group_getname(const struct sysutil_group* p_group)
{
    return p_group->gr_name;
}

/* More random things */
unsigned int sysutil_getpagesize(void)
{
    return getpagesize();
}
unsigned char sysutil_get_random_byte(void)
{
    return ;
}
unsigned int sysutil_get_umask(void)
{
    unsigned int mask = umask(0);
    if(mask < 0)
        die("mask");
    umask(mask);
    return mask;
}
void sysutil_set_umask(unsigned int mask)
{
    umask(mask);
}
void sysutil_make_session_leader(void)
{
    (void)setsid();

    if(sysutil_getpid() != getpgrp())
    {
        die("make session leader");
    }

}
void sysutil_reopen_standard_fds(void)
{
    int fd;
    if((fd = open("/dev/null",O_RDWR)) < 0)
    {
        sysutil_exit(EXIT_FAILURE);
    }

    sysutil_dupfd2(fd,STDIN_FILENO);
    sysutil_dupfd2(fd,STDOUT_FILENO);
    sysutil_dupfd2(fd,STDERR_FILENO);

    if(fd > 2)
    {
        sysutil_close(fd);
    }
}
void sysutil_tzset(void)
{
    tzset();
}
const char* sysutil_get_current_date(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return ctime(&tv.tv_sec);
}
void sysutil_qsort(void* p_base, unsigned int num_elem,
                   unsigned int elem_size,
                   int (*p_compar)(const void *, const void *))
{

}

char* sysutil_getenv(const char* p_var)
{
    return getenv(p_var);
}

void sysutil_set_exit_func(exitfunc_t exitfunc)
{
    int retval;
    retval = atexit(exitfunc);
    if(retval < 0)
        die("atexit");
}
int sysutil_getuid(void)
{
    return getuid();
}

/* Syslogging (bah) */
void sysutil_openlog(int force)
{
    openlog("ftpd",LOG_PID | LOG_CONS,force);
}
void sysutil_syslog(const char* p_text, int severe)
{
    syslog(severe,p_text);
}
void sysutil_closelog(void)
{
    closelog();
}

/* Credentials handling */
int sysutil_running_as_root(void)
{
    //chroot()
    return 0;
}
void sysutil_setuid(const struct sysutil_user* p_user)
{
    int retval;
    retval = setuid(p_user->pw_uid);
    if(retval < 0)
        die("setuid");
}
void sysutil_setgid(const struct sysutil_user* p_user)
{
    int retval;
    retval = setgid(p_user->pw_gid);;
    if(retval < 0)
        die("setegid");
}
void sysutil_setuid_numeric(int uid)
{
    int retval;
    retval = setuid(uid);
    if(retval < 0)
        die("setuid");
}
void sysutil_setgid_numeric(int gid)
{
    int retval;
    retval = setgid(gid);;
    if(retval < 0)
        die("setgid");
}
int sysutil_geteuid(void)
{
    return geteuid();
}
int sysutil_getegid(void)
{
    return getegid();
}
void sysutil_seteuid(const struct sysutil_user* p_user)
{
    int retval;
    retval = seteuid(p_user->pw_uid);;
    if(retval < 0)
        die("seteuid");

}
void sysutil_setegid(const struct sysutil_user* p_user)
{
    int retval;
    retval = setegid(p_user->pw_gid);;
    if(retval < 0)
        die("setegid");
}
void sysutil_seteuid_numeric(int uid)
{
    int retval;
    retval = seteuid(uid);
    if(retval < 0)
        die("seteuid");
}
void sysutil_setegid_numeric(int gid)
{
    int retval;
    retval = setegid(gid);;
    if(retval < 0)
        die("setegid");
}
void sysutil_clear_supp_groups(void)
{

}

void sysutil_initgroups(const struct sysutil_user* p_user)
{

}

void sysutil_chroot(const char* p_root_path)
{
    int retval;
    retval = chroot(p_root_path);
    if(retval < 0)
        die("chroot");
}

/* Time handling */
/* Do not call get_time_usec() without calling get_time_sec()
 * first otherwise you will get stale data.
 */
long sysutil_get_time_sec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_sec;
}
long sysutil_get_time_usec(void)
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv.tv_usec;
}
long sysutil_parse_time(const char* p_text)
{
    return 0;
}
void sysutil_sleep(double seconds)
{
    sleep(seconds);
}
int sysutil_setmodtime(const char* p_file, long the_time, int is_localtime)
{
    struct utimbuf utb;
    int res;
    if(is_localtime)
    {
        res = utime(p_file,NULL);
    }
    else
    {
        utb.modtime = the_time;
        res = utime(p_file,&utb);
    }

    return res;
}

void sysutil_set_address_space_limit(unsigned long bytes)
{

}
void sysutil_set_no_fds()
{
    int res;
    struct rlimit limit;
    limit.rlim_cur = 0;
    limit.rlim_max = 0;

    res = setrlimit(RLIMIT_NOFILE,&limit);
    if(res < 0)
    {
        die("setrlimit");
    }
}

void sysutil_set_no_procs()
{
    int res;
    struct rlimit limit;
    limit.rlim_cur = 0;
    limit.rlim_max = 0;

    res = setrlimit(RLIMIT_NPROC,&limit);
    if(res < 0)
    {
        die("setrlimit");
    }
}

void sysutil_set_sockopt(int fd)
{
    sysutil_set_nodelay(fd);
    sysutil_activate_keepalive(fd);
    sysutil_activate_oobinline(fd);
    //sysutil_activate_linger(fd);
}

void sysutil_clear_fd()
{
    int fd;
    if((fd = open("/dev/null",O_RDWR)) < 0)
    {
        sysutil_exit(EXIT_FAILURE);
    }

    sysutil_dupfd2(fd,STDIN_FILENO);
    sysutil_dupfd2(fd,STDOUT_FILENO);
    sysutil_dupfd2(fd,STDERR_FILENO);

    if(fd > 2)
    {
        sysutil_close(fd);
    }
}

const char *sysutil_uname()
{
    struct utsname sys_name;
    if(uname(&sys_name) < 0)
    {
        die("uname");
    }
    return sys_name.sysname;
}

void sysutil_sendfd(int fd,int sendfd)
{
    struct msghdr msg;
    struct cmsghdr *cmsg = NULL;
    struct iovec iov;

    int *p_fd = NULL;
    char buf[CMSG_SPACE(sizeof(sendfd))];

    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_flags = 0;

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(sendfd));

    p_fd = (int *)CMSG_DATA(cmsg);
    *p_fd = sendfd;

    if(sendmsg(fd,&msg,0) < 0)
    {
        die("recvmsg");
    }
}

void sysutil_recvfd(int fd,int *recvfd)
{
    char char_recv;
    struct msghdr msg;
    struct cmsghdr *cmsg = NULL;
    struct iovec iov;
    iov.iov_base = &char_recv;
    iov.iov_len = sizeof(char_recv);

    char buf[CMSG_SPACE(sizeof(fd))];
    struct sysutil_sockaddr sockaddr;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_flags = 0;

    if(recvmsg(fd,&msg,0) < 0)
    {
        die("recvmsg");
    }
    for(cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; CMSG_NXTHDR(&msg,cmsg))
    {
        if(cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS)
        {
            *recvfd = *(int *)CMSG_DATA(cmsg);
        }
    }
}

void sysutil_prctl(int option)
{
    int retval;
    retval = prctl(option,1);
    if(retval < 0)
        die("prctl");
}

void sysutil_capnetbind()
{
    cap_t caps = cap_init();
    cap_value_t capValue = CAP_NET_BIND_SERVICE;
    unsigned num_caps = 1;
    if(!CAP_IS_SUPPORTED(CAP_NET_BIND_SERVICE))
        die("CAP_NET_BIND_SERVICE not supported");
    cap_set_flag(caps, CAP_EFFECTIVE, num_caps, &capValue, CAP_SET);
    cap_set_flag(caps, CAP_INHERITABLE, num_caps, &capValue, CAP_SET);
    if(cap_set_flag(caps, CAP_PERMITTED, num_caps, &capValue, CAP_SET) < 0)
        die("cap_set_flag");

    if (cap_set_proc(caps) < 0)
        die("cap_set_proc");

    cap_free(caps);
}

const char *sysutil_localnet_ipaddress(struct ftpd_session *session)
{
    struct ifaddrs *if_addrs = NULL;
    struct ifaddrs *if_next = NULL;

    const char *local_ip = sysutil_inet_ntoa(&(session->p_local_addr->u.u_sockaddr_in.sin_addr));
    if(!sysutil_strcmp(local_ip,"127.0.0.1"))
    {
        return local_ip;
    }

    if(getifaddrs(&if_addrs))
    {
        return NULL;
    }

    for(if_next = if_addrs; if_next != NULL; if_next = if_next->ifa_next)
    {
        if(!sysutil_strcmp(if_next->ifa_name,"lo"))
        {
            continue;
        }

        if(if_next->ifa_addr->sa_family == AF_INET)
        {
            return sysutil_inet_ntoa(&(((struct sockaddr_in *)if_next->ifa_addr)->sin_addr));
        }
    }

}

unsigned int sysutil_gettcprtt(int sockfd)
{
    int ret = 0;
    struct tcp_info info;
    socklen_t tcp_info_length = sizeof(info);
    ret = getsockopt(sockfd, SOL_TCP, TCP_INFO, &info, &tcp_info_length);
    if(ret < 0)
    {
        return 0;
    }
    return info.tcpi_rtt;
}





