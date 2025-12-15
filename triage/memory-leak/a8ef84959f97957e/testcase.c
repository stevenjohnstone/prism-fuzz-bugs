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
==46446==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaae784de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaae79e243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaae79e243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaae79e243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaae78bd36c in pm_regexp_token_buffer_escape /prism/src/prism.c:9636:5
    #5 0xaaaae78bd36c in parser_lex /prism/src/prism.c:11422:25
    #6 0xaaaae7951058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaae7953318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #8 0xaaaae79494a0 in parse_pattern /prism/src/prism.c:17023:24
    #9 0xaaaae7950840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #10 0xaaaae7953318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #11 0xaaaae7949114 in parse_pattern /prism/src/prism.c
    #12 0xaaaae7918684 in parse_expression_infix /prism/src/prism.c:21475:34
    #13 0xaaaae78ef204 in parse_expression /prism/src/prism.c:21589:16
    #14 0xaaaae78eb804 in parse_statements /prism/src/prism.c:13163:27
    #15 0xaaaae78ae274 in parse_program /prism/src/prism.c:21810:40
    #16 0xaaaae78ae274 in pm_parse /prism/src/prism.c:22242:12
    #17 0xaaaae79c2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #18 0xaaaae79f4320 in harness /prism/fuzz/parse.c:9:5
    #19 0xaaaae79f44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #20 0xaaaae7886034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #21 0xaaaae7885ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #22 0xaaaae7885988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #23 0xffff85e073fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #24 0xffff85e074d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #25 0xaaaae77af22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in {/00000000000000000\\0"
*/
static const uint8_t input[] = {0x31, 0x69, 0x6e, 0x20, 0x7b, 0x2f, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x5c, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
