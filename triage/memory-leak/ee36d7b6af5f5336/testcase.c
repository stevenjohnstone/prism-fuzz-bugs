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
==74074==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad0c2de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad0dc39e4 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad0dc39e4 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad0dc39e4 in pm_buffer_append_byte /prism/src/util/pm_buffer.c:137:5
    #4 0xaaaad0dc39e4 in pm_buffer_append_unicode_codepoint /prism/src/util/pm_buffer.c:181:9
    #5 0xaaaad0d93730 in escape_write_unicode /prism/src/prism.c:8659:10
    #6 0xaaaad0d93730 in escape_read /prism/src/prism.c:8927:21
    #7 0xaaaad0ca270c in parser_lex /prism/src/prism.c:12059:37
    #8 0xaaaad0d31058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #9 0xaaaad0d32ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #10 0xaaaad0d29114 in parse_pattern /prism/src/prism.c
    #11 0xaaaad0cf8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #12 0xaaaad0ccf204 in parse_expression /prism/src/prism.c:21589:16
    #13 0xaaaad0ce1918 in parse_value_expression /prism/src/prism.c:12430:23
    #14 0xaaaad0ce1918 in parse_expression_prefix /prism/src/prism.c:18162:29
    #15 0xaaaad0cced90 in parse_expression /prism/src/prism.c:21537:23
    #16 0xaaaad0ccb804 in parse_statements /prism/src/prism.c:13163:27
    #17 0xaaaad0c8e274 in parse_program /prism/src/prism.c:21810:40
    #18 0xaaaad0c8e274 in pm_parse /prism/src/prism.c:22242:12
    #19 0xaaaad0da2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #20 0xaaaad0dd4320 in harness /prism/fuzz/parse.c:9:5
    #21 0xaaaad0dd44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #22 0xaaaad0c66034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #23 0xaaaad0c65ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #24 0xaaaad0c65988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #25 0xffffafde73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #26 0xffffafde74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #27 0xaaaad0b8f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in{<<0\n00\\M000000000000000000000000000000\\u{0"
*/
static const uint8_t input[] = {
    0x31, 0x69, 0x6e, 0x7b, 0x3c, 0x3c, 0x30, 0x0a, 0x30, 0x30, 0x5c, 0x4d,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x75, 0x7b, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
