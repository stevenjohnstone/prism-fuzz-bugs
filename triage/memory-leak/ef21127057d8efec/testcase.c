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
==4368==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 128 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad8e0de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad8fa243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad8fa243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad8fa243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaad8f7a530 in pm_token_buffer_flush /prism/src/prism.c:9580:9
    #5 0xaaaad8e82f7c in parser_lex /prism/src/prism.c
    #6 0xaaaad8f11058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaad8f12ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #8 0xaaaad8f09114 in parse_pattern /prism/src/prism.c
    #9 0xaaaad8f10840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #10 0xaaaad8f12ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #11 0xaaaad8f09114 in parse_pattern /prism/src/prism.c
    #12 0xaaaad8f10840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #13 0xaaaad8f12ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #14 0xaaaad8f09114 in parse_pattern /prism/src/prism.c
    #15 0xaaaad8f10840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #16 0xaaaad8f12ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #17 0xaaaad8f09114 in parse_pattern /prism/src/prism.c
    #18 0xaaaad8ed8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #19 0xaaaad8eaf204 in parse_expression /prism/src/prism.c:21589:16
    #20 0xaaaad8eab804 in parse_statements /prism/src/prism.c:13163:27
    #21 0xaaaad8e6e274 in parse_program /prism/src/prism.c:21810:40
    #22 0xaaaad8e6e274 in pm_parse /prism/src/prism.c:22242:12
    #23 0xaaaad8f82800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #24 0xaaaad8fb4320 in harness /prism/fuzz/parse.c:9:5
    #25 0xaaaad8fb44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #26 0xaaaad8e46034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #27 0xaaaad8e45ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #28 0xaaaad8e45988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #29 0xffff879773fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #30 0xffff879774d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #31 0xaaaad8d6f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 128 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in{<<0\n0000000000000000000000000\\ 000000000000000000000000000000000000000"
*/
static const uint8_t input[] = {
    0x31, 0x69, 0x6e, 0x7b, 0x3c, 0x3c, 0x30, 0x0a, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x5c, 0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
