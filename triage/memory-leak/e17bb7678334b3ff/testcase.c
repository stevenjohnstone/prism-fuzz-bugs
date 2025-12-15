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
==3987==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaabd22daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaabd3c1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaabd2a2a14 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaabd2a2a14 in parser_lex /prism/src/prism.c:11907:25
    #4 0xaaaabd331058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #5 0xaaaabd332ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #6 0xaaaabd329114 in parse_pattern /prism/src/prism.c
    #7 0xaaaabd2f8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #8 0xaaaabd2cf204 in parse_expression /prism/src/prism.c:21589:16
    #9 0xaaaabd2e1918 in parse_value_expression /prism/src/prism.c:12430:23
    #10 0xaaaabd2e1918 in parse_expression_prefix /prism/src/prism.c:18162:29
    #11 0xaaaabd2ced90 in parse_expression /prism/src/prism.c:21537:23
    #12 0xaaaabd2cb804 in parse_statements /prism/src/prism.c:13163:27
    #13 0xaaaabd28e274 in parse_program /prism/src/prism.c:21810:40
    #14 0xaaaabd28e274 in pm_parse /prism/src/prism.c:22242:12
    #15 0xaaaabd3a2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #16 0xaaaabd3d4320 in harness /prism/fuzz/parse.c:9:5
    #17 0xaaaabd3d44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #18 0xaaaabd266034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #19 0xaaaabd265ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #20 0xaaaabd265988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #21 0xffff949973fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #22 0xffff949974d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #23 0xaaaabd18f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in{<<0\n\r\n"
*/
static const uint8_t input[] = {0x31, 0x69, 0x6e, 0x7b, 0x3c,
                                0x3c, 0x30, 0x0a, 0x0d, 0x0a};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
