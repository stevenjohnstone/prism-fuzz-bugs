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
==42469==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaadcf4daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaadd0e1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaadcfbf93c in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaadcfbf93c in parser_lex /prism/src/prism.c:11183:21
    #4 0xaaaadcff57cc in parse_expression_prefix /prism/src/prism.c:18070:13
    #5 0xaaaadcfeed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaadcfeb804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaadcfae274 in parse_program /prism/src/prism.c:21810:40
    #8 0xaaaadcfae274 in pm_parse /prism/src/prism.c:22242:12
    #9 0xaaaadd0c2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #10 0xaaaadd0f4320 in harness /prism/fuzz/parse.c:9:5
    #11 0xaaaadd0f44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #12 0xaaaadcf86034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #13 0xaaaadcf85ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #14 0xaaaadcf85988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #15 0xffffaa8a73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #16 0xffffaa8a74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #17 0xaaaadceaf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"A in{%W \#@r\\ "
*/
static const uint8_t input[] = {0x41, 0x20, 0x69, 0x6e, 0x7b, 0x25, 0x57,
                                0x20, 0x23, 0x40, 0x72, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
