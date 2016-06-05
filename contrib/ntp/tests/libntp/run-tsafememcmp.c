/* AUTOGENERATED FILE. DO NOT EDIT. */

//=======Test Runner Used To Run Each Test Below=====
#define RUN_TEST(TestFunc, TestLineNum) \
{ \
  Unity.CurrentTestName = #TestFunc; \
  Unity.CurrentTestLineNumber = TestLineNum; \
  Unity.NumberOfTests++; \
  if (TEST_PROTECT()) \
  { \
      setUp(); \
      TestFunc(); \
  } \
  if (TEST_PROTECT() && !TEST_IS_IGNORED) \
  { \
    tearDown(); \
  } \
  UnityConcludeTest(); \
}

//=======Automagically Detected Files To Include=====
#include "unity.h"
#include <setjmp.h>
#include <stdio.h>
#include "config.h"
#include "ntp_stdlib.h"
#include "isc/string.h"

//=======External Functions This Runner Calls=====
extern void setUp(void);
extern void tearDown(void);
extern void test_Empty(void);
extern void test_Equal(void);
extern void test_FirstByte(void);
extern void test_LastByte(void);
extern void test_MiddleByte(void);
extern void test_MiddleByteUpLo(void);


//=======Test Reset Option=====
void resetTest(void);
void resetTest(void)
{
  tearDown();
  setUp();
}

char const *progname;


//=======MAIN=====
int main(int argc, char *argv[])
{
  progname = argv[0];
  UnityBegin("tsafememcmp.c");
  RUN_TEST(test_Empty, 10);
  RUN_TEST(test_Equal, 11);
  RUN_TEST(test_FirstByte, 12);
  RUN_TEST(test_LastByte, 13);
  RUN_TEST(test_MiddleByte, 14);
  RUN_TEST(test_MiddleByteUpLo, 15);

  return (UnityEnd());
}
