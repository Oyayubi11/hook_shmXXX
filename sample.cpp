#include "stdio.h"
#include "sys/types.h"
#include "sys/ipc.h"
#include "sys/shm.h"
#include "string.h"
#include "stdlib.h"

#define PAGESIZE 4096
#define SHMSIZE 1024

class sample{
private:
  int shmid;
  void * shmaddr;
public :
  void init();
  void exec();
  void release();
};

void sample::init(){
  shmid = shmget(IPC_PRIVATE,SHMSIZE,IPC_CREAT|0666);
  if( shmid == -1 ){
    printf("shmget error\n");
    exit(1);
  }

  printf("create shm\n");
}

void sample::exec(){
  shmaddr = shmat(shmid, (void *)0, 0 );
  if( shmaddr == (char*)-1){
    printf("shmat error\n");
    exit(1);
  }

  printf("attached shm");
}

void sample::release(){
  if( shmdt(shmaddr) == -1 ){
    printf("shmdt error\n");
    exit(1);
  }
  
  printf("detached shared memory.\n");

  if( shmctl(shmid, IPC_RMID, 0) == -1 ){
    printf("shmctl error\n");
    exit(1);
  }
  printf("deleted shared memory\n");
}

int main( int argc, char * argv[] ){
  sample s;
  s.init();
  s.exec();
  s.release();
  return 0;
}
