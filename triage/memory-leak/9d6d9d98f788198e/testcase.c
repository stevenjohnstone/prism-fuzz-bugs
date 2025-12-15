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
==888==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaada49daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaada631518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaada50e3b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaada50e3b8 in parser_lex /prism/src/prism.c:11685:25
    #4 0xaaaada5a1058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #5 0xaaaada5a2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #6 0xaaaada599114 in parse_pattern /prism/src/prism.c
    #7 0xaaaada568684 in parse_expression_infix /prism/src/prism.c:21475:34
    #8 0xaaaada53f204 in parse_expression /prism/src/prism.c:21589:16
    #9 0xaaaada53b804 in parse_statements /prism/src/prism.c:13163:27
    #10 0xaaaada4fe274 in parse_program /prism/src/prism.c:21810:40
    #11 0xaaaada4fe274 in pm_parse /prism/src/prism.c:22242:12
    #12 0xaaaada612800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #13 0xaaaada644320 in harness /prism/fuzz/parse.c:9:5
    #14 0xaaaada6444c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #15 0xaaaada4d6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #16 0xaaaada4d5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #17 0xaaaada4d5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #18 0xffffa6ce73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #19 0xffffa6ce74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #20 0xaaaada3ff22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"[in{:'\\0"
*/
static const uint8_t input[] = {0x5b, 0x69, 0x6e, 0x7b, 0x3a, 0x27, 0x5c, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
