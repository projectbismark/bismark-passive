#include "constants.h"
#include "http_parser.h"
#include "http_table.h"

#include <assert.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

static void add_url(http_table_t* http_table,
                         uint16_t flow_id,
                         char * ul,
                         int len)
                         {
  http_url_entry entry;
  entry.flow_id = flow_id;
  entry.url=strdup(ul);
  http_table_add_url(http_table, &entry);
//  printf("%s %d\n",entry.url, entry.url);
#ifndef NDEBUG
  fprintf(stderr,
          "Request URL entry %d: %s %d\n",
          http_table->length,
          entry.url,
          entry.flow_id);
#endif
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
   printf("%s %d\n",vec[0],n);   
   vec[n]=strtok(NULL, " ");
//   printf("%d %s\n",n,vec[n]);
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
   printf("What is there: %s %s\n",argv[0],argv[1]);
   if(!strcasecmp(argv[0],"GET")) // a GET command
    printf("retrieved %s size %u \n",argv[1], (int)strlen(argv[1]));
   else return -1; 
  }  
  else return -1;
  int flagcut=0;
  int length=(int)strlen(argv[1]);
  if(length>MAX_URL)
    {argv[1][MAX_URL-1]='\0';
//     strncpy(str,argv[1],MAX_HTTP_URL);  
     flagcut=1;
    } 
  add_url(http_table, flow_id,argv[1],flagcut);
  return 0;
}
