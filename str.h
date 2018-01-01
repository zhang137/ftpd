#ifndef STR_H_INCLUDED
#define STR_H_INCLUDED


struct mystr
{
  char* pbuf;
  /* Internally, EXCLUDES trailing null */
  unsigned int num_len;
  unsigned int alloc_bytes;
};



#endif // STR_H_INCLUDED
