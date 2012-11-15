#include "Lib_hook.h"

#include <dlfcn.h>
#include <netdb.h>
#include <syslog.h>
#include <pwd.h>
#include <sstream>

#include <errno.h>
#include <execinfo.h>
#include <assert.h>

using namespace std;

Lib_hook::Lib_hook()
{
  setup_log();
  setup_symbols();

  //元の関数ポインタを取得しておく                                                                      
  original_shmget = (int(*)(key_t key, size_t size, int shmflg)) dlsym(REAL_LIBC, "shmget" );
  original_shmdt =  (int(*)(const void *shmaddr)) dlsym(REAL_LIBC, "shmdt" );
  original_shmctl = (int(*)(int shmid, int cmd, struct shmid_ds *buf)) dlsym(REAL_LIBC, "shmctl");
  original_shmat =  (void *(*)(int shmid, const void *shmaddr, int shmflg)) dlsym(REAL_LIBC, "shmat"); 

}

Lib_hook::~Lib_hook(){
  close_log();
  close_symbols();
}


//実行バイナリ名、PIDからログファイル生成                                      
void Lib_hook::setup_log(){
  ostringstream os;

  const int BUF_SIZE = 0xFFFF;
  char buf[BUF_SIZE];
  char fullpath[BUF_SIZE];

  //実行バイナリのPID取得
  pid_t pid = getpid();
  snprintf(buf, BUF_SIZE, "/proc/%d/exe", pid );
  // /proc/xxx/exeは実行バイナリのシンボリックリンクなので
  // シンボリックリンクの宛先をbufに格納する。
  int ret = readlink(buf, fullpath, BUF_SIZE);

  if( -1 == ret ){
    return;
  }

  //logファイル名設定＋logファイルオープン                                     
  os << fullpath << "_" << pid << ".log";
  LOGGER.open(os.str().c_str());

  //自身の実行ファイル名もついでにほじっておく                                 
  LOG_NAME = fullpath;

  return;
}

//LOGGERクローズ                                                               
void Lib_hook::close_log(){
  LOGGER.close();
  return;
}

//関数情報出力準備                                                             
void Lib_hook::setup_symbols(){
  long storage;
  int i;
  int ret;

  abfd = bfd_openr(LOG_NAME.c_str(), NULL);
  assert( abfd );

  ret = bfd_check_format(abfd, bfd_object);
  assert( ret );

  if(!(bfd_get_file_flags(abfd) & HAS_SYMS)){
    //bfd読み込み失敗なので終了
    assert( bfd_get_error() == bfd_error_no_error );
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
    addr2Sym.insert( map<long, long>::value_type( value, (long)sym) );
  }
}

const char * Lib_hook::symbol2name( void * addr ){
  if( NULL == addr ){
    return NULL;
  }else{
    asymbol * sym = (asymbol *)addr2Sym[(long)addr];
    return bfd_asymbol_name(sym);
  }
}

void Lib_hook::close_symbols(){
  if( NULL != syms ){
    free(syms);
  }

  if( NULL != abfd ){
    bfd_close(abfd);
  }

  //mapは終了時に開放されるから、消さなくてもいっか                            

  return;
}

void Lib_hook::show_debug_info( void * addr ){
  Dl_info info;                                                                             

  //とりあえずdllから引っ張ってみる
  //dll照会失敗したらbfd使う
  if( !dladdr(addr, &info) ){ 
    goto GET_DEBUG_INFO;
  }
  
  //Name of nearest symbol with address lower than addr
  //dll名無いときはbfd使う
  if( !info.dli_sname || !info.dli_saddr ){
    goto GET_DEBUG_INFO;
  }

  //ここまでくればdllから情報抜き出し成功
  cout << "0x" << addr << "@" << info.dli_fname << ":" << info.dli_sname << endl;
  return;

  //bfd使ってdebug情報から関数がコールされているファイル名と行数を取得
GET_DEBUG_INFO:
  asection * dbgsec = bfd_get_section_by_name(abfd, ".debug_info");

  if( NULL == dbgsec ){
    cout << "0x" << addr << ":" << "???@???:???";
    return;
  }

  const char * file_name;
  const char * function_name;
  char * demangled;

  unsigned int line = 0;
  int found = bfd_find_nearest_line(abfd,
				    dbgsec, 
				    syms,
                                    (long)addr,
                                    &file_name,
                                    &function_name,
                                    &line);
  int status = 0;

  if( !found || NULL == file_name ) file_name = "???";

  //関数取得できなかったときはシンボル情報から頑張って探す
  if( !found || NULL == function_name ) function_name = symbol2name(addr);
  if( NULL == function_name ) function_name = "???";
  
  //デマングル demangledはmallocされたアドレスが入るので後でfreeすること
  demangled = abi::__cxa_demangle(function_name, 0, 0, &status);
  cout << "0x" << addr << ":" << demangled << "@" << file_name << ":" << line << endl;
  if( demangled ){
    free( demangled );
  }    

  return;
}

//関数名をデマングルして出力  
// ./hook_shmXXX.so(_Z15print_backtracev+0x56) [0xa0001d]
void Lib_hook::print_demangled_bt( const char * str ){
  if( NULL == str ){
    return;
  }

  string name = str;

  //関数名抜きだし
  string::size_type left = name.find("(");
  string::size_type right= name.find("+", left + 1);

  string func;
  string bin;
  if( left == name.npos || right == name.npos ){
    func == "";
    //backtrace情報が想定外だったら諦めてそのまま出力
    LOGGER << "  nBT  " << str << endl;
    return;
  }else{
    bin  = name.substr( 0, left );
    func = name.substr( left + 1, right - left - 1 );
  }

  string addr;
  left = name.find("[");
  right= name.find("]", left + 1);
  if( left == name.npos || right == name.npos ){
    addr == "";
    //backtrace情報が想定外だったら諦めてそのまま出力
    LOGGER << "  nBT  " << str << endl;
    return;
  }else{
    addr = name.substr( left + 1, right - left - 1 );
    long value;
    std::istringstream is(addr);
    is >> std::hex >> value;
    show_debug_info( (void *)value );
  }

  int status;
  char * demangled = abi::__cxa_demangle(func.c_str(), 0, 0, &status);

  if( NULL != demangled ){
    LOGGER << "  BT  " << bin << ":" << demangled;
    free(demangled);
  }else{
    LOGGER << "  nBT " << str << endl;
    return;
  }

  if( addr != "" ){
    LOGGER << " [" << addr << "]" << endl;
  }

  return;
}

void Lib_hook::print_backtrace(){
  cout << "print_backtrace()" << endl;
  void *trace[1024];
  int n = backtrace(trace, sizeof(trace)/sizeof(trace[0]));

  char ** traceStrings = backtrace_symbols(trace, n);

  if( NULL == traceStrings ){
    cout << "not found bt" << endl;
    return;
  }

  for(int i = 0; i < n; i++){
    print_demangled_bt(traceStrings[i]);
  }
  free(traceStrings);
}

int Lib_hook::shmget(key_t key, size_t size, int shmflg){
  // 元の関数を呼び出す                                                                                 
  int ret = (*original_shmget)(key, size, shmflg);

  // errnoの保存                                                                                        
  int org_errno = errno;

  LOGGER << "==== call shmget ====" << endl;
  LOGGER << " key    = " << key << " @";
  LOGGER << " size   = " << size << " @";
  LOGGER << " shmflg = " << shmflg << endl;

  //backtrace出力                                                                                       
  print_backtrace();

  LOGGER << "---- end shmget ----" << endl;

  // errnoの復旧                                                                                        
  org_errno = errno;

  return ret;
}

void * Lib_hook::shmat(int shmid, const void * shmaddr, int shmflg){
  void * ret = (*original_shmat)(shmid, shmaddr, shmflg);

  // errnoの保存                                                                                        
  int org_errno = errno;

  LOGGER << "==== call shmat ====" << endl;
  LOGGER << " shmid   = " << shmid << " @";
  LOGGER << " shmaddr = " << shmaddr << " @";
  LOGGER << " shmflg  = " << shmflg << endl;

  //backtrace出力                                                                                       
  print_backtrace();

  LOGGER << "---- end shmat ----" << endl;

  // errnoの復旧                                                                                        
  org_errno = errno;

  return ret;
}

int Lib_hook::shmdt(const void *shmaddr){
  int ret = (*original_shmdt)(shmaddr);

  // errnoの保存                                                                                        
  int org_errno = errno;

  LOGGER << "==== call shmdt ====" << endl;
  LOGGER << " shmaddr = " << shmaddr << endl;

  //backtrace出力                                                                                       
  print_backtrace();

  LOGGER << "---- end shmdt ----" << endl;

  // errnoの復旧                                                                                        
  org_errno = errno;

  return ret;
}

int Lib_hook::shmctl(int shmid, int cmd, struct shmid_ds *buf){
  int ret = (*original_shmctl)(shmid, cmd, buf);

  // errnoの保存                                                                                        
  int org_errno = errno;

  LOGGER << "==== call shmctl ====" << endl;
  LOGGER << " shmid = " << shmid << " @";
  LOGGER << " cmd   = " << cmd << " @";
  LOGGER << " buf   = " << buf << endl;

  //backtrace出力                                                                                       
  print_backtrace();

  LOGGER << "---- end shmctl ----" << endl;

  // errnoの復旧                                                                                        
  org_errno = errno;

  return ret;
}
