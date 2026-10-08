#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc,char **argv) {
  if(argc!=2) return 2;
  for(int i=0;i<4100;i++) {
    pid_t p=fork();if(p<0)return 3;
    if(!p){char *args[]={argv[1],0};execv(argv[1],args);_exit(errno==ENOEXEC?0:4);}
    int status;if(waitpid(p,&status,0)!=p||!WIFEXITED(status)||WEXITSTATUS(status))return 5;
  }
  return 0;
}
