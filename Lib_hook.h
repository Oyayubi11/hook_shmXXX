#ifndef _HOOK_SHMXXX_H_
#define _HOOK_SHMXXX_H_

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include <set>
#include <map>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <typeinfo>
#include <cxxabi.h>
#include <bfd.h>

#if defined(RTLD_NEXT)
#define REAL_LIBC RTLD_NEXT
#else
#define REAL_LIBC ((void *) -1L)
#endif

#define SADDR_B(target,shift) (((target) >> (shift)) & 0x000000ff)

class Lib_hook{
private:
  // オリジナルの関数のポインタ
  int (*original_shmget)(key_t key, size_t size, int shmflg); 
  void * (*original_shmat) (int shmid, const void *shmaddr, int shmflg);
  int (*original_shmdt) (const void *shmaddr);
  int (*original_shmctl)(int shmid, int cmd, struct shmid_ds *buf);

  //ログ出力用ostream;
  std::ofstream LOGGER;

  //ログファイル名
  std::string LOG_NAME;

  //デマングル用
  bfd * abfd;
  asymbol ** syms;
  int symnum;
  std::map<long, long> addr2Sym;

public:
  Lib_hook();
  ~Lib_hook();
  void setup_log();
  void close_log();
  void setup_symbols();
  void close_symbols();
  void show_debug_info( void * addr );
  void print_demangled_bt( const char * str );
  void print_backtrace();

  int shmget(key_t key, size_t size, int shmflg);
  void * shmat(int shmid, const void * shmaddr, int shmflg);
  int shmdt(const void *shmaddr);
  int shmctl(int shmid, int cmd, struct shmid_ds *buf);
};

#endif  //_HOOK_SHMXXX_H_
