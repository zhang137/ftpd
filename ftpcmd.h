#ifndef FTPCMD_H_INCLUDED
#define FTPCMD_H_INCLUDED

#include "session.h"
#include "str.h"

/*
*服务器在一个非标准端口上收听数据连接。
*/
void handle_pasv(struct ftpd_session *session, struct mystr *str_arg);
/*
*远程系统上的用户名称
*/
void handle_user(struct ftpd_session *session, struct mystr *str_arg);
/*
* 服务器中止上一次FTP服务命令及所有相关的数据传输。
*/
void handle_pass(struct ftpd_session *session, struct mystr *str_arg);
/*
*为数据连接指定一个IP地址和本地端口。
*/
void handle_abot();
/*
*当前目录改为远程文件系统的根目录，无需改变登录、帐号信息或传输参数
*/
void handle_cdup();
/*
*应答中返回当前工作目录的名称
*/
void handle_pwd();
/*
*删除服务器站点上在路径名中指定的文件。
*/
void handle_dele();
/*
*服务器通过到客户的控制连接发送有关其实现状态的帮助信息。
*/
void handle_help();
/*
*服务器给客户发送一份列表。
*/
void handle_list();
/*
*创建一个在路径名中指定的目录（如果是绝对路径名）或当前工作目录的子目录（如果是相对路径名）。
*/
void handle_mkd();
/*
*说明：指定传输模式。
*用法：STRU<Mode><CRLF>
*参数：Mode是如下ASCII值的其中之一：
*S——Stream（流，默认值）
*B——Block（块）
*C——Compressed（经过压缩）
*/
void handle_mode();
/*
*让服务器发送一条OK应答外，它不指定任何操作。
*/
void handle_noop();
/*
*向远程系统发送用户的密码，该命令在USER命令后使用。
*/
void handle_port();
/*
*终止连接
*/
void handle_quit();
/*
*标识出文件内的数据点，将从这个点开始继续传送文件
*/
void handle_rest();
/*
*让服务器给客户传送一份在路径名中指定的文件的副本。这不会影响该文件在服务器站点上的状态和内容。
*/
void handle_retr();
/*
*删除一个在路径名中指定的目录（如果是绝对路径名）或当前工作目录的子目录（如果是相对路径名）。
*/
void handle_rmd();
/*
*文件重命名进程的前一半。指定要重命名的文件的旧路径和文件名
*/
void handle_rnfr();
/*
*指定传达数据的结构类型 STRU<Structure Type><CRLF>
*/
void handle_stor();
/*
*让服务器准备接收一个文件，并指示服务器把这个文件用唯一的名称保存到目的目录中
*/
void handle_stou();
/*
*让服务器准备接收一个文件并指示它把这些数据附加到指定的文件名，如果指定的文件尚未存在，就创建它。
*/
void handle_appe();
/*
*
*/
void handle_syst(struct ftpd_session *session);



#endif // FTPCMD_H_INCLUDED
