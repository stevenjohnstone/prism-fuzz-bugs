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

=================================================================
==69609==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 2 object(s) allocated from:
    #0 0xaaaaad5edaa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaaad781518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaaad65d2fc in pm_regexp_token_buffer_escape /prism/src/prism.c:9628:9
    #3 0xaaaaad65d2fc in parser_lex /prism/src/prism.c:11422:25
    #4 0xaaaaad6f1058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #5 0xaaaaad6f2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #6 0xaaaaad6e9114 in parse_pattern /prism/src/prism.c
    #7 0xaaaaad6edc2c in parse_pattern_hash /prism/src/prism.c:16435:29
    #8 0xaaaaad6e8f0c in parse_pattern /prism/src/prism.c:16938:20
    #9 0xaaaaad6b8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #10 0xaaaaad68f204 in parse_expression /prism/src/prism.c:21589:16
    #11 0xaaaaad68b804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaaad64e274 in parse_program /prism/src/prism.c:21810:40
    #13 0xaaaaad64e274 in pm_parse /prism/src/prism.c:22242:12
    #14 0xaaaaad762800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #15 0xaaaaad794320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaaad7944c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaaad626034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaaad625ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaaad625988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffffac3b73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffffac3b74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaaad54f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 2 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
" 1in a:{/\\0/ c in a:{/\\0"
*/
static const uint8_t input[] = {0x20, 0x31, 0x69, 0x6e, 0x20, 0x61, 0x3a, 0x7b,
                                0x2f, 0x5c, 0x30, 0x2f, 0x20, 0x63, 0x20, 0x69,
                                0x6e, 0x20, 0x61, 0x3a, 0x7b, 0x2f, 0x5c, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
