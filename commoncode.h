#ifndef COMMONCODE_H_INCLUDED
#define COMMONCODE_H_INCLUDED

#define FTPD_CMDWRIO  0
#define FTPD_CMDRDIO  1

#define FTPD_DATAPORT 20
#define FTPD_CMDPORT 21
#define FTPD_CMDDATA_LEN 1024
#define FTPD_DATA_LEN 4096
#define FTPD_UNIXSOCK_LEN 1024

enum PUNIXCMDSTATUS
{
    PCMDRESPONDLOGINOK = 1,
    PCMDRESPONDLOGINFAIL,
    PCMDRESPONDPORTOK,
    PCMDRESPONDPORTFAIL,
    PCMDRESPONDLIST,                  //add
    PCMDRESPONDLISTOK,
    PCMDRESPONDLISTFAIL,
    PCMDRESPONDPASV,                  //add
    PCMDRESPONDPASVOK,
    PCMDRESPONDPASVFAIL,
    PCMDRESPONDSIZEOK,
    PCMDRESPONDSIZEFAIL,
    PCMDRESPONDMDTMOK,
    PCMDRESPONDMDTMFAIL,
    PCMDRESPONDCWDOK,
    PCMDRESPONDCWDFAIL,
    PCMDRESPONDRETROK,
    PCMDRESPONDRETRFAIL,
    PCMDRESPONDSTOROK,
    PCMDRESPONDSTORFAIL,
    PCMDRESPONDCDUPOK,
    PCMDRESPONDCDUPFAIL,
    PCMDRESPONDPWDOK,
    PCMDRESPONDPWDFAIL,
    PCMDRESPONDTYPEOK,
    PCMDRESPONDTYPEFAIL,
    PCMDRESPONDMKDOK,
    PCMDRESPONDMKDFAIL,
    PCMDRESPONDRESTOK,
    PCMDRESPONDRESTFAIL,
    PCMDRESPONDRMDOK,
    PCMDRESPONDRMDFAIL,
    PCMDRESPONDDELEOK,
    PCMDRESPONDDELEFAIL,
};

enum PUNIXCMDTYPE
{
    PCMDREQUESTLOGIN = 1,
    PCMDREQUESTPWD,
    PCMDREQUESTPORT,
    PCMDREQUESTRETR,
    PCMDREQUESTSTOR,
    PCMDREQUESTSTOU,
    PCMDREQUESTAPPE,
    PCMDREQUESTPASV,
    PCMDREQUESTTYPE,
    PCMDREQUESTSIZE,
    PCMDREQUESTMDTM,
    PCMDREQUESTCDUP,
    PCMDREQUESTCWD,
    PCMDREQUESTDELE,
    PCMDREQUESTLIST,
    PCMDREQUESTMKD,
    PCMDREQUESTNOOP,
    PCMDREQUESTREST,
    PCMDREQUESTRMD,


};


#endif // COMMONCODE_H_INCLUDED
