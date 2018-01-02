#ifndef SYSUTIL_H_INCLUDED
#define SYSUTIL_H_INCLUDED

#include <netinet/in.h>
#include "filesize.h"

struct sysutil_sockaddr
{
  union
  {
    struct sockaddr u_sockaddr;
    struct sockaddr_in u_sockaddr_in;
    struct sockaddr_in6 u_sockaddr_in6;
  } u;
};



enum EVSFSysUtilError
{
  kVSFSysUtilErrUnknown = 1,
  kVSFSysUtilErrADDRINUSE,
  kVSFSysUtilErrNOSYS,
  kVSFSysUtilErrINTR,
  kVSFSysUtilErrINVAL,
  kVSFSysUtilErrOPNOTSUPP,
  kVSFSysUtilErrACCES,
  kVSFSysUtilErrNOENT
};
/* Signal handling utility functions */
enum EVSFSysUtilSignal
{
  kVSFSysUtilSigALRM = 1,
  kVSFSysUtilSigTERM,
  kVSFSysUtilSigCHLD,
  kVSFSysUtilSigPIPE,
  kVSFSysUtilSigURG,
  kVSFSysUtilSigHUP
};
enum EVSFSysUtilInterruptContext
{
  kVSFSysUtilUnknown,
  kVSFSysUtilIO
};

typedef void (*sighandle_t)(void*);
typedef void (*async_sighandle_t)(int);
typedef void (*context_io_t)(int, int, void*);

enum EVSFSysUtilError sysutil_get_error(void);
int sysutil_retval_is_error(int retval);
void sysutil_install_null_sighandler(const enum EVSFSysUtilSignal sig);
void sysutil_install_sighandler(const enum EVSFSysUtilSignal,
                                    async_sighandle_t handler,
                                    void* p_private,
                                    int use_alarm);
void sysutil_install_async_sighandler(const enum EVSFSysUtilSignal sig,
                                          async_sighandle_t handler);
void sysutil_default_sig(const enum EVSFSysUtilSignal sig);
void sysutil_install_io_handler(context_io_t handler, void* p_private);
void sysutil_uninstall_io_handler(void);
void sysutil_check_pending_actions(
  const enum EVSFSysUtilInterruptContext context, int retval, int fd);
void sysutil_block_sig(const enum EVSFSysUtilSignal sig);
void sysutil_unblock_sig(const enum EVSFSysUtilSignal sig);

/* Alarm setting/clearing utility functions */
void sysutil_set_alarm(const unsigned int trigger_seconds);
void sysutil_clear_alarm(void);

/* Directory related things */
char* sysutil_getcwd(char* p_dest, const unsigned int buf_size);
int sysutil_mkdir(const char* p_dirname, const unsigned int mode);
int sysutil_rmdir(const char* p_dirname);
int sysutil_chdir(const char* p_dirname);
int sysutil_rename(const char* p_from, const char* p_to);

struct sysutil_dir;
struct sysutil_dir* sysutil_opendir(const char* p_dirname);
void sysutil_closedir(struct sysutil_dir* p_dir);
const char* sysutil_next_dirent(struct sysutil_dir* p_dir);

/* File create/open/close etc. */
enum EVSFSysUtilOpenMode
{
  kVSFSysUtilOpenReadOnly = 1,
  kVSFSysUtilOpenWriteOnly,
  kVSFSysUtilOpenReadWrite
};

int sysutil_open_file(const char* p_filename,
                          const enum EVSFSysUtilOpenMode);
/* Fails if file already exists */
int sysutil_create_file_exclusive(const char* p_filename);
/* Creates file or appends if already exists */
int sysutil_create_or_open_file_append(const char* p_filename,
                                           unsigned int mode);
/* Creates or appends */
int sysutil_create_or_open_file(const char* p_filename, unsigned int mode);
void sysutil_dupfd2(int old_fd, int new_fd);
void sysutil_close(int fd);
int sysutil_close_failok(int fd);
int sysutil_unlink(const char* p_dead);
int sysutil_write_access(const char* p_filename);
void sysutil_ftruncate(int fd);

/* Reading and writing */
void sysutil_lseek_to(const int fd, filesize_t seek_pos);
void ysutil_lseek_end(const int fd);
filesize_t sysutil_get_file_offset(const int file_fd);
int sysutil_read(const int fd, void* p_buf, const unsigned int size);
int sysutil_write(const int fd, const void* p_buf,
                      const unsigned int size);
/* Reading and writing, with handling of interrupted system calls and partial
 * reads/writes. Slightly more usable than the standard UNIX API!
 */
int sysutil_read_loop(const int fd, void* p_buf, unsigned int size);
int sysutil_write_loop(const int fd, const void* p_buf, unsigned int size);

struct sysutil_statbuf;
int sysutil_stat(const char* p_name, struct sysutil_statbuf** p_ptr);
int sysutil_lstat(const char* p_name, struct sysutil_statbuf** p_ptr);
void sysutil_fstat(int fd, struct sysutil_statbuf** p_ptr);
void sysutil_dir_stat(const struct sysutil_dir* p_dir,
                          struct sysutil_statbuf** p_ptr);
int sysutil_statbuf_is_regfile(const struct sysutil_statbuf* p_stat);
int sysutil_statbuf_is_symlink(const struct sysutil_statbuf* p_stat);
int sysutil_statbuf_is_socket(const struct sysutil_statbuf* p_stat);
int sysutil_statbuf_is_dir(const struct sysutil_statbuf* p_stat);
filesize_t sysutil_statbuf_get_size(
  const struct sysutil_statbuf* p_stat);
const char* sysutil_statbuf_get_perms(
  const struct sysutil_statbuf* p_stat);
const char* sysutil_statbuf_get_date(
  const struct sysutil_statbuf* p_stat, int use_localtime, long curr_time);
const char* sysutil_statbuf_get_numeric_date(
  const struct sysutil_statbuf* p_stat, int use_localtime);
unsigned int sysutil_statbuf_get_links(
  const struct sysutil_statbuf* p_stat);
int sysutil_statbuf_get_uid(const struct sysutil_statbuf* p_stat);
int sysutil_statbuf_get_gid(const struct sysutil_statbuf* p_stat);
int sysutil_statbuf_is_readable_other(
  const struct sysutil_statbuf* p_stat);
const char* sysutil_statbuf_get_sortkey_mtime(
  const struct sysutil_statbuf* p_stat);

int sysutil_chmod(const char* p_filename, unsigned int mode);
void sysutil_fchown(const int fd, const int uid, const int gid);
void sysutil_fchmod(const int fd, unsigned int mode);
int sysutil_readlink(const char* p_filename, char* p_dest,
                         unsigned int bufsiz);

/* Get / unget various locks. Lock gets are blocking. Write locks are
 * exclusive; read locks are shared.
 */
int sysutil_lock_file_write(int fd);
int sysutil_lock_file_read(int fd);
void sysutil_unlock_file(int fd);

/* Mapping/unmapping */
enum EVSFSysUtilMapPermission
{
  kVSFSysUtilMapProtReadOnly = 1,
  kVSFSysUtilMapProtNone
};
void sysutil_memprotect(void* p_addr, unsigned int len,
                            const enum EVSFSysUtilMapPermission perm);
void sysutil_memunmap(void* p_start, unsigned int length);

/* Memory allocating/freeing */
void* sysutil_malloc(unsigned int size);
void* sysutil_realloc(void* p_ptr, unsigned int size);
void sysutil_free(void* p_ptr);

/* Process creation/exit/process handling */
unsigned int sysutil_getpid(void);
void sysutil_post_fork(void);
int sysutil_fork(void);
int sysutil_fork_failok(void);
void sysutil_exit(int exit_code);
struct sysutil_wait_retval
{
  int PRIVATE_HANDS_OFF_syscall_retval;
  int PRIVATE_HANDS_OFF_exit_status;
};
struct sysutil_wait_retval sysutil_wait(void);
int sysutil_wait_reap_one(void);
int sysutil_wait_get_retval(
  const struct sysutil_wait_retval* p_waitret);
int sysutil_wait_exited_normally(
  const struct sysutil_wait_retval* p_waitret);
int sysutil_wait_get_exitcode(
  const struct sysutil_wait_retval* p_waitret);

/* Various string functions */
unsigned int sysutil_strlen(const char* p_text);
char* sysutil_strdup(const char* p_str);
void sysutil_memclr(void* p_dest, unsigned int size);
void sysutil_memcpy(void* p_dest, const void* p_src,
                        const unsigned int size);
void sysutil_strcpy(char* p_dest, const char* p_src, unsigned int maxsize);
int sysutil_memcmp(const void* p_src1, const void* p_src2,
                       unsigned int size);
int sysutil_strcmp(const char* p_src1, const char* p_src2);
int sysutil_atoi(const char* p_str);
filesize_t sysutil_a_to_filesize_t(const char* p_str);
const char* sysutil_ulong_to_str(unsigned long the_ulong);
const char* sysutil_filesize_t_to_str(filesize_t the_filesize);
const char* sysutil_double_to_str(double the_double);
const char* sysutil_uint_to_octal(unsigned int the_uint);
unsigned int sysutil_octal_to_uint(const char* p_str);
int sysutil_toupper(int the_char);
int sysutil_isspace(int the_char);
int sysutil_isprint(int the_char);
int sysutil_isalnum(int the_char);
int sysutil_isdigit(int the_char);

/* Socket handling */
struct sysutil_sockaddr;
struct sysutil_socketpair_retval
{
  int socket_one;
  int socket_two;
};
void sysutil_sockaddr_alloc(struct sysutil_sockaddr** p_sockptr);
void sysutil_sockaddr_clear(struct sysutil_sockaddr** p_sockptr);
void sysutil_sockaddr_alloc_ipv4(struct sysutil_sockaddr** p_sockptr);
void sysutil_sockaddr_alloc_ipv6(struct sysutil_sockaddr** p_sockptr);
void sysutil_sockaddr_clone(
  struct sysutil_sockaddr** p_sockptr,
  const struct sysutil_sockaddr* p_src);
int sysutil_sockaddr_addr_equal(const struct sysutil_sockaddr* p1,
                                    const struct sysutil_sockaddr* p2);
int sysutil_sockaddr_is_ipv6(
  const struct sysutil_sockaddr* p_sockaddr);
void sysutil_sockaddr_set_ipv4addr(struct sysutil_sockaddr* p_sockptr,
                                       const unsigned char* p_raw);
void sysutil_sockaddr_set_ipv6addr(struct sysutil_sockaddr* p_sockptr,
                                       const unsigned char* p_raw);
void sysutil_sockaddr_set_any(struct sysutil_sockaddr* p_sockaddr);
unsigned short sysutil_sockaddr_get_port(
    const struct sysutil_sockaddr* p_sockptr);
void sysutil_sockaddr_set_port(struct sysutil_sockaddr* p_sockptr,
                                   unsigned short the_port);
int sysutil_is_port_reserved(unsigned short port);
int sysutil_get_ipsock(const struct sysutil_sockaddr* p_sockaddr);
unsigned int sysutil_get_ipaddr_size(void);
void* sysutil_sockaddr_get_raw_addr(
  struct sysutil_sockaddr* p_sockaddr);
const void* sysutil_sockaddr_ipv6_v4(
  const struct sysutil_sockaddr* p_sockaddr);
const void* sysutil_sockaddr_ipv4_v6(
  const struct sysutil_sockaddr* p_sockaddr);
int sysutil_get_ipv4_sock(void);
int sysutil_get_ipv6_sock(void);
struct sysutil_socketpair_retval
  sysutil_unix_stream_socketpair(void);
int sysutil_bind(int fd, const struct sysutil_sockaddr* p_sockptr);
int sysutil_listen(int fd, const unsigned int backlog);
void sysutil_getsockname(int fd, struct sysutil_sockaddr** p_sockptr);
void sysutil_getpeername(int fd, struct sysutil_sockaddr** p_sockptr);
int sysutil_accept_timeout(int fd, struct sysutil_sockaddr* p_sockaddr,
                               unsigned int wait_seconds);
int sysutil_connect_timeout(int fd,
                                const struct sysutil_sockaddr* p_sockaddr,
                                unsigned int wait_seconds);
void sysutil_dns_resolve(struct sysutil_sockaddr** p_sockptr,
                             const char* p_name);
/* Option setting on sockets */
void sysutil_activate_keepalive(int fd);
void sysutil_set_iptos_throughput(int fd);
void sysutil_activate_reuseaddr(int fd);
void sysutil_set_nodelay(int fd);
void sysutil_activate_sigurg(int fd);
void sysutil_activate_oobinline(int fd);
void sysutil_activate_linger(int fd);
void sysutil_deactivate_linger_failok(int fd);
void sysutil_activate_noblock(int fd);
void sysutil_deactivate_noblock(int fd);
/* This does SHUT_RDWR */
void sysutil_shutdown_failok(int fd);
/* And this does SHUT_RD */
void sysutil_shutdown_read_failok(int fd);
int sysutil_recv_peek(const int fd, void* p_buf, unsigned int len);

const char* sysutil_inet_ntop(
  const struct sysutil_sockaddr* p_sockptr);
const char* sysutil_inet_ntoa(const void* p_raw_addr);
int sysutil_inet_aton(
  const char* p_text, struct sysutil_sockaddr* p_addr);

/* User database queries etc. */
struct sysutil_user;
struct sysutil_group;

struct sysutil_user* sysutil_getpwuid(const int uid);
struct sysutil_user* sysutil_getpwnam(const char* p_user);
const char* sysutil_user_getname(const struct sysutil_user* p_user);
const char* sysutil_user_get_homedir(
  const struct sysutil_user* p_user);
int sysutil_user_getuid(const struct sysutil_user* p_user);
int sysutil_user_getgid(const struct sysutil_user* p_user);

struct sysutil_group* sysutil_getgrgid(const int gid);
const char* sysutil_group_getname(const struct sysutil_group* p_group);

/* More random things */
unsigned int sysutil_getpagesize(void);
unsigned char sysutil_get_random_byte(void);
unsigned int sysutil_get_umask(void);
void sysutil_set_umask(unsigned int umask);
void sysutil_make_session_leader(void);
void sysutil_reopen_standard_fds(void);
void sysutil_tzset(void);
const char* sysutil_get_current_date(void);
void sysutil_qsort(void* p_base, unsigned int num_elem,
                       unsigned int elem_size,
                       int (*p_compar)(const void *, const void *));
char* sysutil_getenv(const char* p_var);
typedef void (*exitfunc_t)(void);
void sysutil_set_exit_func(exitfunc_t exitfunc);
int sysutil_getuid(void);

/* Syslogging (bah) */
void sysutil_openlog(int force);
void sysutil_syslog(const char* p_text, int severe);
void sysutil_closelog(void);

/* Credentials handling */
int sysutil_running_as_root(void);
void sysutil_setuid(const struct sysutil_user* p_user);
void sysutil_setgid(const struct sysutil_user* p_user);
void sysutil_setuid_numeric(int uid);
void sysutil_setgid_numeric(int gid);
int sysutil_geteuid(void);
int sysutil_getegid(void);
void sysutil_seteuid(const struct sysutil_user* p_user);
void sysutil_setegid(const struct sysutil_user* p_user);
void sysutil_seteuid_numeric(int uid);
void sysutil_setegid_numeric(int gid);
void sysutil_clear_supp_groups(void);
void sysutil_initgroups(const struct sysutil_user* p_user);
void sysutil_chroot(const char* p_root_path);

/* Time handling */
/* Do not call get_time_usec() without calling get_time_sec()
 * first otherwise you will get stale data.
 */
long sysutil_get_time_sec(void);
long sysutil_get_time_usec(void);
long sysutil_parse_time(const char* p_text);
void sysutil_sleep(double seconds);
int sysutil_setmodtime(const char* p_file, long the_time, int is_localtime);

/* Limits */
void sysutil_set_address_space_limit(unsigned long bytes);
void sysutil_set_no_fds(void);
void sysutil_set_no_procs(void);


#endif // SYSUTIL_H_INCLUDED
