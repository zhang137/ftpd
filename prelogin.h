#ifndef PRELOGIN_H_INCLUDED
#define PRELOGIN_H_INCLUDED

#include "sysutil.h"

//void progress_credentials(struct mystr *user)
void init_connection();
struct mystr get_cmd_from_client();

#endif // PRELOGIN_H_INCLUDED
