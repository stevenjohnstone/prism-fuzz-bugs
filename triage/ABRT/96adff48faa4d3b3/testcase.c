#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define _GNU_SOURCE
#include <prism.h>

__attribute__((noinline)) void harness(const uint8_t *input, size_t size) {
  pm_buffer_t buffer;
  pm_buffer_init(&buffer);
  pm_serialize_parse(&buffer, input, size, NULL);
  pm_buffer_free(&buffer);
}

/*
fuzz: src/serialize.c:22: uint32_t pm_ptrdifft_to_u32(ptrdiff_t): Assertion `value >= 0 && ((unsigned long) value) < UINT32_MAX' failed.
AddressSanitizer:DEADLYSIGNAL
=================================================================
==33597==ERROR: AddressSanitizer: ABRT on unknown address 0x03e80000833d (pc 0xffff99192008 bp 0xffffc8e63ab0 sp 0xffffc8e63a20 T0)
    #0 0xffff99192008 in __pthread_kill_implementation nptl/pthread_kill.c:44:76
    #1 0xffff9914a838 in gsignal signal/../sysdeps/posix/raise.c:26:13
    #2 0xffff99137130 in abort stdlib/abort.c:79:7
    #3 0xffff99144110 in __assert_fail_base assert/assert.c:94:3
    #4 0xffff99144188 in __assert_fail assert/assert.c:103:3
    #5 0xaaaad6959f78 in pm_serialize_location /prism/src/serialize.c
    #6 0xaaaad695a87c in pm_serialize_diagnostic /prism/src/serialize.c:2105:5
    #7 0xaaaad695a87c in pm_serialize_diagnostic_list /prism/src/serialize.c:2116:9
    #8 0xaaaad6942e00 in pm_serialize_metadata /prism/src/serialize.c:2138:5
    #9 0xaaaad6942e00 in pm_serialize_content /prism/prism/templates/src/serialize.c.erb:280:5
    #10 0xaaaad6942e00 in pm_serialize_parse /prism/src/prism.c:22413:5
    #11 0xaaaad6974320 in harness /prism/fuzz/parse.c:9:5
    #12 0xaaaad69744c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #13 0xaaaad6806034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #14 0xaaaad6805ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #15 0xaaaad6805988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #16 0xffff991373fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #17 0xffff991374d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #18 0xaaaad672f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: ABRT nptl/pthread_kill.c:44:76 in __pthread_kill_implementation
==33597==ABORTING

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"/(?<\\uddef>/=~ "
*/
static const uint8_t input[] = {0x2f, 0x28, 0x3f, 0x3c, 0x5c, 0x75, 0x64, 0x64,
                                0x65, 0x66, 0x3e, 0x2f, 0x3d, 0x7e, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
