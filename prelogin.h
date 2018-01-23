#ifndef PRELOGIN_H_INCLUDED
#define PRELOGIN_H_INCLUDED

#include "sysutil.h"

void init_connection(struct ftpd_session *session);
struct mystr get_cmd_from_client();

#endif // PRELOGIN_H_INCLUDED
