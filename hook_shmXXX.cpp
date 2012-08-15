/*
* hook_shmXXX.so
*
* == author
* ayabe
*
* == about
* LD_PRELOADを利用して、プログラム中で実行される
* shmget/shmat/shmdt/shmctl()の情報をlogへ記録するプログラムです。
* Linux環境で動作確認を行っています。
*
* == ベースファイル
* http://www.t-dori.net/forensics/hook_tcp.cpp
*
* == compile
* $ g++ -Wall -fPIC -shared -o hook_tcp.so hook_tcp.cpp -ldl
*
* == how to use
* 通常のプログラムを実行する際に、環境変数でLD_PRELOAD=./hook_tcp.soを
* 指定しておきます。hook_shmXXX.soはshmXXX関数を使用するプログラムであれば、
* どのようなプログラムでも使用することができます。
*
* $ LD_PRELOAD=./hook_tcp.so ./a.out
*
* == mechanism
* LD_PRELOADでsoファイルを指定しておくと、プログラム中に含まれている
* 関数をsoファイルに含まれている関数に置き換えることができます。
*
* ただし、そのまま置き換えただけでは、元の関数が呼び出されなくなってしまうので、
*
* [関数呼び出し元] -> [置き換えた関数] -> [オリジナルの関数]
*
* という感じで、soで置き換えた関数の中からオリジナルの関数を呼ぶようにして、
* 置き換えた関数の中で、ログを出力するようにしています。
*
* hook_shmXXX.soは共有メモリを操作する関数をフックして、共有メモリ操作情報を
* logへ出力するようにしています。
*
*/
#include <dlfcn.h>
#include <netdb.h>
#include <syslog.h>
#include <pwd.h>
#include <iostream>
#include <set>
#include <string>
#include <sstream>
#include <fstream>

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <unistd.h>
#include <typeinfo>
#include <cxxabi.h>
#include <stdio.h>
#include <stdlib.h>
#include <bfd.h>
#include <map>

#if defined(RTLD_NEXT)
#define REAL_LIBC RTLD_NEXT
#else
#define REAL_LIBC ((void *) -1L)
#endif

using namespace std;

// オリジナルの関数のポインタ
static int (*original_shmget)(key_t key, size_t size, int shmflg) = NULL;
static void * (*original_shmat) (int shmid, const void *shmaddr, int shmflg) = NULL;
static int (*original_shmdt) (const void *shmaddr) = NULL;
static int (*original_shmctl)(int shmid, int cmd, struct shmid_ds *buf) = NULL;

#define SADDR_B(target,shift) (((target) >> (shift)) & 0x000000ff)

ofstream LOGGER;
string FNAME;

//実行バイナリ名、PIDからログファイル生成
static void set_log(){
  ostringstream os;
  
  char buf[256];
  char fullpath[1024];
  
  pid_t pid = getpid();
  sprintf(buf, "/proc/%d/exe", pid );
  int ret = readlink(buf, fullpath, 1024);
  
  if( -1 == ret ){
    return;
  }
  
  //logファイル名設定＋logファイルオープン
  os << fullpath << "_" << pid << ".log";
  LOGGER.open(os.str().c_str());
  
  //自身の実行ファイル名もついでにほじっておく
  FNAME = fullpath;

  return;
}

//LOGGERクローズ
static void close_log(){
  LOGGER.close();
  return;
}

static bfd * abfd = NULL;
static asymbol ** syms = NULL;
static int symnum;
static map<long, asymbol *> addr2Sym;

//関数情報出力準備
void setup_symbols(){
  long storage;
  int i;
  int ret;
  
  abfd = bfd_openr(FNAME.c_str(), NULL);
  ret = bfd_check_format(abfd, bfd_object);
  
  if(!(bfd_get_file_flags(abfd) & HAS_SYMS)){
    bfd_close(abfd);
    return;
  }
  
  storage = bfd_get_symtab_upper_bound(abfd);
  
  if(storage) {
    syms = (asymbol **)malloc(storage);
  }
  
  symnum = bfd_canonicalize_symtab(abfd, syms);

  asymbol * sym;
  long value;
  for( i = 0; i < symnum; i++ ){
    sym = syms[i];
    value = bfd_asymbol_value(sym);
    addr2Sym[value] = sym;
  }
}

void close_symbols(){
  if( NULL != syms ){
    free(syms);
  }
  
  if( NULL != abfd ){
    bfd_close(abfd);
  }
  
  //mapは終了時に開放されるから、消さなくてもいっか
  
  return;
}

void show_debug_info( void * addr ){
  
/*
  Dl_info info;
  
  if( !dladdr(addr, &info) ){
  cout << "0x" << addr << ":???@???:???" << endl;
  return;
  }
  
  //Name of nearest symbol with address lower than addr
  if( !info.dli_sname ){
  cout << "0x" << addr << ":" << function_name << "@" << info.dli_fname << ":???" << endl;
  return;
  }
  
  //Exact address of symbol named in dli_sname
  if( !info.dli_saddr ){
  cout << "0x" << addr << ":" << function_name << "@" << info.dli_fname << ":" << info.dli_sname << endl;
  return;
  }
*/

//debug情報から関数がコールされているファイル名と行数を取得
  asection * dbgsec = bfd_get_section_by_name(abfd, ".debug_info");
  
  const char * file_name;
  const char * function_name;
  unsigned int line;
  int found = bfd_find_nearest_line(abfd, dbgsec, syms,
				    (long)addr,
				    &file_name,
				    &function_name,
				    &line);
  
  int status = 0;
  char * demangled = NULL;
  
  //読み込み成功
  if( found && NULL != file_name && NULL != function_name ){
    //デマングル demangledはmallocされたアドレスが入るので後でfreeすること
    demangled = abi::__cxa_demangle(function_name, 0, 0, &status);
    cout << "0x" << addr << ":" << demangled << "@" << file_name << ":" << line << endl;
  }else{
    //デバッグ情報読み込み失敗したので、関数名だけ頑張って取得
    map<long, asymbol *> addr2Sym;
    
    asymbol * sym = addr2Sym[addr];
    if( NULL == sym ){
      cout << "0x" << addr << ":???" << "@" << "???:???" << endl;
    }else{
      function_name = bfd_asymbol_name(sym);
      demangled = abi::__cxa_demangle(function_name, 0, 0, &status);
      cout << "0x" << addr << ":" << demangled << "@" << "???:???" << endl;
    }
  }
  
  if( demangled ){
    free( demangled );
  }
  
  return;
}

//backtrace出力のための設定
typedef struct layout {
  struct layout *ebp;
  void *ret;
} layout;

void print_backtrace(){
  layout *ebp = (layout*) __builtin_frame_address(0);
  while(ebp){
    show_debug_info( ebp->ret );
    ebp =ebp->ebp;
  }
}

static void __attribute__ ((constructor))
_constructor()
{
  // for logger
  set_log();
  
  // for backtrace
  setup_symbols();
  
  //元の関数ポインタを取得しておく
  original_shmget = (int(*)(key_t key, size_t size, int shmflg)) dlsym(REAL_LIBC, "shmget" );
  original_shmat =  ((void *)(*)(int shmid, const void *shmaddr, int shmflg)) dlsym(REAL_LIBC, "shmat");
  original_shmdt =  (int(*)(const void *shmaddr)) dlsym(REAL_LIBC, "shmdt" );
  original_shmctl = (int(*)(int shmid, int cmd, struct shmid_ds *buf)) dlsym(REAL_LIBC, "shmctl");
  return;
}

static void __attribute__ ((destructor))
_destructor()
{
  close_log();
  close_symbols();
  return;
}


int shmget(key_t key, size_t size, int shmflg)
{
  // 元の関数を呼び出す
int ret = (*original_shmget)(key, size, shmflg);

// errnoの保存
int org_errno = errno;

LOGGER << "==== call shmget ====" << endl;
LOGGER << " key = " << key << "@";
LOGGER << " size = " << size << "@";
LOGGER << " shmflg = " << shmflg << endl;

//backtrace出力
print_backtrace();

LOGGER << "==== end shmget ====" << endl;

// errnoの復旧
org_errno = errno;

return ret;
}

int shmat(int shmid, const void *shmaddr, int shmflg){
int ret = (*original_shmat)(shmid, shmaddr, shmflg);

// errnoの保存
int org_errno = errno;

LOGGER << "==== call shmat ====" << endl;
LOGGER << " shmid = " << shmid << "@";
LOGGER << " shmaddr = " << shmaddr << "@";
LOGGER << " shmflg = " << shmflg << endl;

//backtrace出力
print_backtrace();

LOGGER << "==== end shmat ====" << endl;

// errnoの復旧
org_errno = errno;

return ret;
}


int shmdt(const void *shmaddr){
int ret = (*original_shmdt)(shmaddr);

// errnoの保存
int org_errno = errno;

LOGGER << "==== call shmdt ====" << endl;
LOGGER << " shmaddr = " << shmaddr << "@";

//backtrace出力
print_backtrace();

LOGGER << "==== end shmdt ====" << endl;

// errnoの復旧
org_errno = errno;

return ret;
}

int shmctl(int shmid, int cmd, struct shmid_ds *buf){
int ret = (*original_shmctl)(shmid, cmd, buf);

// errnoの保存
int org_errno = errno;

LOGGER << "==== call shmctl ====" << endl;
LOGGER << " shmid = " << shmid << "@";
LOGGER << " cmd = " << cmd << "@";
LOGGER << " buf = " << buf << "@";

//backtrace出力
print_backtrace();

LOGGER << "==== end shmctl ====" << endl;

// errnoの復旧
org_errno = errno;

return ret;
}
