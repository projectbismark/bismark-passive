#include "constants.h"
#include "http_parser.h"
#include "http_table.h"

#include <assert.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include "anonymization.h"

int add_url(http_table_t* http_table,
                         uint16_t flow_id,
                         char * ul,
                         int len)
                         {
  http_url_entry entry;
  entry.flow_id = flow_id;
  printf("http url %s\n",ul);
  unsigned char url_digest[ANONYMIZATION_DIGEST_LENGTH];
  if (anonymize_url(ul, url_digest)){
   fprintf(stderr, "Error anonymizing URLs\n");
      return -1;
   }
  entry.url=(unsigned char *) strdup((const char*)url_digest);
  http_table_add_url(http_table, &entry);
#ifndef NDEBUG
  fprintf(stderr,
          "Request URL entry %d: %s %d\n",
          http_table->length,
          entry.url,
          entry.flow_id);
#endif
return 0;
}

/*
 * Split a string in components delimited by 'delimiter'
  */
static int
tokenize(char *buf, char **vec, int vecsize, int delimiter)
{
 int n = 0;
 
 vec[n]=strtok(buf," ");
 n++; 
 while(n<vecsize)
 {
   vec[n]=strtok(NULL, " ");
   if(vec[n]==NULL) return n+1;
   n++; 
 }   

 return n;
}
                                                                        
int process_http_packet(const uint8_t* const bytes,
                       int len,
                       http_table_t* const http_table,
                       uint16_t flow_id)
{
  if (len <=0) return -1;
  char * argv[3];
  int n;
  if((n=tokenize((char*)bytes,argv,3,' ')) ==3) {
   if(!strcasecmp(argv[0],"GET")) // a GET command
    printf("retrieved %s size %u \n",argv[1], (int)strlen(argv[1]));
   else return -1; 
  }  
  else return -1;
  int flagcut=0;
  int length=(int)strlen(argv[1]);
  if(length>MAX_URL)
    {argv[1][MAX_URL-1]='\0';
     flagcut=1;
    } 
  printf("received http request\n");
#ifndef DISABLE_ANONYMIZATION
  add_url(http_table, flow_id,argv[1],flagcut);
#endif
  return 0;
}
