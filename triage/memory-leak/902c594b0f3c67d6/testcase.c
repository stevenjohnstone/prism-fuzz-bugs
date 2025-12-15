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
==80425==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaae653daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaae66d1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaae65af93c in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaae65af93c in parser_lex /prism/src/prism.c:11183:21
    #4 0xaaaae65dbb2c in parse_statements /prism/src/prism.c:13204:13
    #5 0xaaaae659e274 in parse_program /prism/src/prism.c:21810:40
    #6 0xaaaae659e274 in pm_parse /prism/src/prism.c:22242:12
    #7 0xaaaae66b2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #8 0xaaaae66e4320 in harness /prism/fuzz/parse.c:9:5
    #9 0xaaaae66e44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #10 0xaaaae6576034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #11 0xaaaae6575ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #12 0xaaaae6575988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #13 0xffffaf2073fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #14 0xffffaf2074d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #15 0xaaaae649f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"\"\"in a:{%I  \\="
*/
static const uint8_t input[] = {0x22, 0x22, 0x69, 0x6e, 0x20, 0x61, 0x3a,
                                0x7b, 0x25, 0x49, 0x20, 0x20, 0x5c, 0x3d};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
