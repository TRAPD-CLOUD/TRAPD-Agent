#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc!=3) return 2;
  int flags=atoi(argv[2]);
  int fd=open(argv[1],flags);
  fprintf(stderr,"probe flags=%d opened=%d\n",flags,fd>=0);
  if (fd>=0 && flags==0) { char b[8]; if(read(fd,b,sizeof b)<0) return 6; }
  if (fd>=0) {
    void *anonymous=mmap(0,4096,PROT_READ,MAP_PRIVATE|MAP_ANONYMOUS,fd,0);
    if(anonymous==MAP_FAILED) return 8;
    munmap(anonymous,4096);
    void *mapped=mmap(0,4096,PROT_READ,MAP_PRIVATE,fd, flags==2?1:0);
    int expected_failure=(flags & O_PATH) || (flags & O_ACCMODE)==O_WRONLY || flags==2;
    if ((mapped==MAP_FAILED)!=expected_failure) return 7;
    if(mapped!=MAP_FAILED)munmap(mapped,4096);
  }
  sleep(2);
  if(fd>=0) close(fd);
  return ((flags==O_DIRECTORY) == (fd<0)) ? 0 : 1;
}
