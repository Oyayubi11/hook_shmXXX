#include <iostream>
#include <cppunit/TestRunner.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/extensions/HelperMacros.h>
#include <cppunit/BriefTestProgressListener.h>
#include <cppunit/extensions/TestFactoryRegistry.h>

#include "../Lib_hook.h"

class Test : public CPPUNIT_NS::TestCase{
  CPPUNIT_TEST_SUITE(Test);
  CPPUNIT_TEST(test_Lib_hook);
  CPPUNIT_TEST(test_Lib_hook_);
  CPPUNIT_TEST(test_setup_log);
  CPPUNIT_TEST(test_close_log);
  CPPUNIT_TEST(test_setup_symbols);
  CPPUNIT_TEST(test_close_symbols);
  CPPUNIT_TEST(test_show_debug_info);
  CPPUNIT_TEST(test_print_demangled_bt);
  CPPUNIT_TEST(test_print_backtrace);
  CPPUNIT_TEST(test_shmget);
  CPPUNIT_TEST(test_shmat);
  CPPUNIT_TEST(test_shmdt);
  CPPUNIT_TEST(test_shmctl);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp(void);
  void tearDown(void);
  
protected:
  void test_Lib_hook(void);
  void test_Lib_hook_(void);
  void test_setup_log(void);
  void test_close_log(void);
  void test_setup_symbols(void);
  void test_close_symbols(void);
  void test_show_debug_info(void);
  void test_print_demangled_bt(void);
  void test_print_backtrace(void);
  void test_shmget(void);
  void test_shmat(void);
  void test_shmdt(void);
  void test_shmctl(void);
};

void Test::setUp(void){

}

void Test::tearDown(void){

}

void Test::test_Lib_hook(void){

}
void Test::test_Lib_hook_(void){

}
void Test::test_setup_log(void){

}
void Test::test_close_log(void){

}
void Test::test_setup_symbols(void){

}
void Test::test_close_symbols(void){

}
void Test::test_show_debug_info(void){

}
void Test::test_print_demangled_bt(void){

}
void Test::test_print_backtrace(void){

}
void Test::test_shmget(void){

}
void Test::test_shmat(void){

}
void Test::test_shmdt(void){

}
void Test::test_shmctl(void){

}

CPPUNIT_TEST_SUITE_REGISTRATION(Test);

int main(int argc, char * argv[]){
  CPPUNIT_NS::TestResult controller;
 
  CPPUNIT_NS::TestResultCollector result;
  controller.addListener( &result );

  CPPUNIT_NS::BriefTestProgressListener progress;
  controller.addListener( &progress );

  CPPUNIT_NS::TestRunner runner;
  runner.addTest( CPPUNIT_NS::TestFactoryRegistry::getRegistry().makeTest() );
  runner.run( controller );

  return result.wasSuccessful() ? 0 : 1;
}
