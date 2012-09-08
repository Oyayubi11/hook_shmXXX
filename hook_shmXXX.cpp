#include "Lib_hook.h"
#include <assert.h>

static Lib_hook * p_hook = NULL;

//main関数実行前にshmXXX関数フッククラスを初期化
static void __attribute__ ((constructor))
_constructor()
{
  try {
    p_hook = new Lib_hook();
  }catch (...){
    p_hook = NULL;
  }
  return;
}

//main関数実行後にshmXXX関数フッククラス終了処理
static void __attribute__ ((destructor))
_destructor()
{
  if( p_hook ){
    delete p_hook;
  }
  return;
}

//shmXXX関数を再定義することで、任意の処理に置換する。
int shmget(key_t key, size_t size, int shmflg){
  assert( NULL != p_hook );
  return p_hook->shmget( key, size, shmflg );
}

void * shmat(int shmid, const void * shmaddr, int shmflg){
  assert( NULL != p_hook );
  return p_hook->shmat( shmid, shmaddr, shmflg );
}

int shmdt(const void *shmaddr){
  assert( NULL != p_hook );
  return p_hook->shmdt(shmaddr);
}

int shmctl(int shmid, int cmd, struct shmid_ds *buf){
  assert( NULL != p_hook );
  return p_hook->shmctl(shmid, cmd, buf);
}
