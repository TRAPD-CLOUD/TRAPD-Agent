#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
static void *run(void *arg) { char **v=arg; char *a[]={v[1],v[2],"0",0};execv(v[1],a);_exit(3); }
int main(int argc,char **argv) { if(argc!=3)return 2;pthread_t t;if(pthread_create(&t,0,run,argv))return 4;pthread_join(t,0);return 5; }
