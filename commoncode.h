#ifndef COMMONCODE_H_INCLUDED
#define COMMONCODE_H_INCLUDED


uint16_t FTPD_CMDPORT 20;

const char *trunable_nobody = "nobody";
enum
{
    RECV_CMD_FD = 0x01,
    SEND_CMD_FD = 0x02,

    FTP_ANOUYMOUS = 0x10,
    FTP_AUTHOK

};


#endif // COMMONCODE_H_INCLUDED
