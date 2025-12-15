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
fuzz: src/serialize.c:36: void pm_serialize_location(const pm_parser_t *, const pm_location_t *, pm_buffer_t *): Assertion `location->start <= location->end' failed.
AddressSanitizer:DEADLYSIGNAL
=================================================================
==393==ERROR: AddressSanitizer: ABRT on unknown address 0x03e800000189 (pc 0xffffa0ae2008 bp 0xfffff8c22d80 sp 0xfffff8c22cf0 T0)
    #0 0xffffa0ae2008 in __pthread_kill_implementation nptl/pthread_kill.c:44:76
    #1 0xffffa0a9a838 in gsignal signal/../sysdeps/posix/raise.c:26:13
    #2 0xffffa0a87130 in abort stdlib/abort.c:79:7
    #3 0xffffa0a94110 in __assert_fail_base assert/assert.c:94:3
    #4 0xffffa0a94188 in __assert_fail assert/assert.c:103:3
    #5 0xaaaac2629f20 in pm_serialize_location /prism/src/serialize.c:36:5
    #6 0xaaaac261b72c in pm_serialize_node /prism/src/serialize.c:88:5
    #7 0xaaaac2622964 in pm_serialize_node /prism/src/serialize.c:951:17
    #8 0xaaaac2620c18 in pm_serialize_node /prism/src/serialize.c:1816:17
    #9 0xaaaac26252c0 in pm_serialize_node /prism/src/serialize.c
    #10 0xaaaac2620c18 in pm_serialize_node /prism/src/serialize.c:1816:17
    #11 0xaaaac26252c0 in pm_serialize_node /prism/src/serialize.c
    #12 0xaaaac2620c18 in pm_serialize_node /prism/src/serialize.c:1816:17
    #13 0xaaaac2612e90 in pm_serialize_content /prism/prism/templates/src/serialize.c.erb:291:5
    #14 0xaaaac2612e90 in pm_serialize_parse /prism/src/prism.c:22413:5
    #15 0xaaaac2644320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaac26444c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaac24d6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaac24d5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaac24d5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffffa0a873fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffffa0a874d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaac23ff22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: ABRT nptl/pthread_kill.c:44:76 in __pthread_kill_implementation
==393==ABORTING

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"a\x81a[do a[do{not "
*/
static const uint8_t input[] = {0x61, 0x81, 0x61, 0x5b, 0x64, 0x6f, 0x20, 0x61,
                                0x5b, 0x64, 0x6f, 0x7b, 0x6e, 0x6f, 0x74, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
