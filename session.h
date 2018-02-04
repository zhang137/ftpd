#ifndef SESSION_H_INCLUDED
#define SESSION_H_INCLUDED

#include "filesize.h"
#include "sysutil.h"
#include "strlist.h"

struct ftpd_session
{
  /* Details of the control connection */
  struct sysutil_sockaddr* p_local_addr;
  struct sysutil_sockaddr* p_remote_addr;
  char* p_control_line_buf;
  int idle_timeout;
  int data_timeout;

  /* Details of the data connection */
  int pasv_listen_fd;
  struct sysutil_sockaddr* p_port_sockaddr;
  int data_fd;
  int data_progress;
  unsigned int bw_rate_max;
  long bw_send_start_sec;
  long bw_send_start_usec;

  /* Details of the login */
  int is_anonymous;
  struct mystr user_str;
  struct mystr passwd_str;

  /* Details of the FTP protocol state */
  filesize_t restart_pos;
  int is_ascii;
  int is_pasv;
  struct mystr rnfr_filename_str;
  int abor_received;

  /* Details of FTP session state */
  struct mystr_list* p_visited_dir_list;

  /* Things we need to cache before we chroot() */
  struct mystr userlist_str;
  struct mystr banner_str;

  /* Logging related details */
  struct mystr remote_ip_str;
  long log_start_sec;
  long log_start_usec;
  filesize_t transfer_size;

  /* Buffers */
  struct mystr ftp_cmd_str;
  struct mystr ftp_arg_str;

  /* Parent<->child comms channel */
  int parent_fd;
  int child_fd;

  /* Other details */
  unsigned int num_clients;
  unsigned int num_this_ip;
  struct mystr home_str;

  unsigned int login_fails;
};


//struct vsf_session
//{
//  /* Details of the control connection */
//  struct vsf_sysutil_sockaddr* p_local_addr;
//  struct vsf_sysutil_sockaddr* p_remote_addr;
//  char* p_control_line_buf;
//  int idle_timeout;
//  int data_timeout;
//
//  /* Details of the data connection */
//  int pasv_listen_fd;
//  struct vsf_sysutil_sockaddr* p_port_sockaddr;
//  int data_fd;
//  int data_progress;
//  unsigned int bw_rate_max;
//  long bw_send_start_sec;
//  long bw_send_start_usec;
//
//  /* Details of the login */
//  int is_anonymous;
//  int is_guest;
//  struct mystr user_str;
//  struct mystr anon_pass_str;
//
//  /* Details of the FTP protocol state */
//  filesize_t restart_pos;
//  int is_ascii;
//  struct mystr rnfr_filename_str;
//  int abor_received;
//  int epsv_all;
//
//  /* Details of FTP session state */
//  struct mystr_list* p_visited_dir_list;
//
//  /* Details of userids which are interesting to us */
//  int anon_ftp_uid;
//  int guest_user_uid;
//  int anon_upload_chown_uid;
//
//  /* Things we need to cache before we chroot() */
//  struct mystr banned_email_str;
//  struct mystr email_passwords_str;
//  struct mystr userlist_str;
//  struct mystr banner_str;
//  int tcp_wrapper_ok;
//
//  /* Logging related details */
//  int xferlog_fd;
//  int vsftpd_log_fd;
//  struct mystr remote_ip_str;
//  unsigned long log_type;
//  long log_start_sec;
//  long log_start_usec;
//  struct mystr log_str;
//  filesize_t transfer_size;
//
//  /* Buffers */
//  struct mystr ftp_cmd_str;
//  struct mystr ftp_arg_str;
//
//  /* Parent<->child comms channel */
//  int parent_fd;
//  int child_fd;
//
//  /* Other details */
//  unsigned int num_clients;
//  unsigned int num_this_ip;
//  struct mystr home_str;
//
//};
//


#endif // SESSION_H_INCLUDED
