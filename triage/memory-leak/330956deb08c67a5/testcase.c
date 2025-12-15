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
==52560==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 6 byte(s) in 1 object(s) allocated from:
    #0 0xaaaabf84de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaabf9e3ba4 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaabf9e3ba4 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaabf9e3ba4 in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaabf9e3ba4 in pm_buffer_append_unicode_codepoint /prism/src/util/pm_buffer.c:189:9
    #5 0xaaaabf9b3730 in escape_write_unicode /prism/src/prism.c:8659:10
    #6 0xaaaabf9b3730 in escape_read /prism/src/prism.c:8927:21
    #7 0xaaaabf8cc524 in lex_question_mark /prism/src/prism.c:9226:9
    #8 0xaaaabf8cc524 in parser_lex /prism/src/prism.c:10502:21
    #9 0xaaaabf8fa88c in parse_expression_prefix /prism/src/prism.c:19725:25
    #10 0xaaaabf8eed90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaabf8eb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaabf9661ec in parse_string_part /prism/src/prism.c:15372:30
    #13 0xaaaabf8fb0e4 in parse_expression_prefix /prism/src/prism.c
    #14 0xaaaabf8eed90 in parse_expression /prism/src/prism.c:21537:23
    #15 0xaaaabf920db8 in parse_value_expression /prism/src/prism.c:12430:23
    #16 0xaaaabf920db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #17 0xaaaabf920db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #18 0xaaaabf91cc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #19 0xaaaabf8ef204 in parse_expression /prism/src/prism.c:21589:16
    #20 0xaaaabf8eb804 in parse_statements /prism/src/prism.c:13163:27
    #21 0xaaaabf8fe23c in parse_expression_prefix /prism/src/prism.c:19312:30
    #22 0xaaaabf8eed90 in parse_expression /prism/src/prism.c:21537:23
    #23 0xaaaabf8eb804 in parse_statements /prism/src/prism.c:13163:27
    #24 0xaaaabf8ae274 in parse_program /prism/src/prism.c:21810:40
    #25 0xaaaabf8ae274 in pm_parse /prism/src/prism.c:22242:12
    #26 0xaaaabf9c2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #27 0xaaaabf9f4320 in harness /prism/fuzz/parse.c:9:5
    #28 0xaaaabf9f44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #29 0xaaaabf886034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #30 0xaaaabf885ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #31 0xaaaabf885988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #32 0xffffa61073fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #33 0xffffa61074d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #34 0xaaaabf7af22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Direct leak of 3 byte(s) in 1 object(s) allocated from:
    #0 0xaaaabf84daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaabf9e1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaabf8cc510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaabf8cc510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaabf8fa88c in parse_expression_prefix /prism/src/prism.c:19725:25
    #5 0xaaaabf8eed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaabf8eb804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaabf9661ec in parse_string_part /prism/src/prism.c:15372:30
    #8 0xaaaabf8fb0e4 in parse_expression_prefix /prism/src/prism.c
    #9 0xaaaabf8eed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaabf920db8 in parse_value_expression /prism/src/prism.c:12430:23
    #11 0xaaaabf920db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #12 0xaaaabf920db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #13 0xaaaabf91cc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #14 0xaaaabf8ef204 in parse_expression /prism/src/prism.c:21589:16
    #15 0xaaaabf8eb804 in parse_statements /prism/src/prism.c:13163:27
    #16 0xaaaabf8fe23c in parse_expression_prefix /prism/src/prism.c:19312:30
    #17 0xaaaabf8eed90 in parse_expression /prism/src/prism.c:21537:23
    #18 0xaaaabf8eb804 in parse_statements /prism/src/prism.c:13163:27
    #19 0xaaaabf8ae274 in parse_program /prism/src/prism.c:21810:40
    #20 0xaaaabf8ae274 in pm_parse /prism/src/prism.c:22242:12
    #21 0xaaaabf9c2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #22 0xaaaabf9f4320 in harness /prism/fuzz/parse.c:9:5
    #23 0xaaaabf9f44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #24 0xaaaabf886034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #25 0xaaaabf885ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #26 0xaaaabf885988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #27 0xffffa61073fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #28 0xffffa61074d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #29 0xaaaabf7af22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 9 byte(s) leaked in 2 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"while}\n% \#{end ?\\u{de aA "
*/
static const uint8_t input[] = {0x77, 0x68, 0x69, 0x6c, 0x65, 0x7d, 0x0a,
                                0x25, 0x20, 0x23, 0x7b, 0x65, 0x6e, 0x64,
                                0x20, 0x3f, 0x5c, 0x75, 0x7b, 0x64, 0x65,
                                0x20, 0x61, 0x41, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
