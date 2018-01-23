#ifndef COMMONCODE_H_INCLUDED
#define COMMONCODE_H_INCLUDED

int FTP_CMDWRIO  = 0;
int FTP_CMDRDIO  = 1;

unsigned short FTPD_DATAPORT = 20;
unsigned short FTPD_CMDPORT = 21;

unsigned int FTPD_CMDDATA_LEN  = 4096;

const char *tunable_nobody = "nobody";
enum
{
    RECV_CMD_FD = 0x01,
    SEND_CMD_FD = 0x02,

    FTP_ANOUYMOUS = 0x10,
    FTP_AUTHOK

};


#endif // COMMONCODE_H_INCLUDED
