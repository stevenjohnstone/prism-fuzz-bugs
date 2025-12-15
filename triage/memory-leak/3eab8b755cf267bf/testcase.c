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
==57403==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 12 byte(s) in 1 object(s) allocated from:
    #0 0xaaaae136de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaae1503f6c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaae1503f6c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaae1503f6c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaae1503f6c in pm_buffer_append_unicode_codepoint /prism/src/util/pm_buffer.c:208:9
    #5 0xaaaae14d3730 in escape_write_unicode /prism/src/prism.c:8659:10
    #6 0xaaaae14d3730 in escape_read /prism/src/prism.c:8927:21
    #7 0xaaaae13ec524 in lex_question_mark /prism/src/prism.c:9226:9
    #8 0xaaaae13ec524 in parser_lex /prism/src/prism.c:10502:21
    #9 0xaaaae1486144 in parse_string_part /prism/src/prism.c:15452:13
    #10 0xaaaae14277a0 in parse_expression_prefix /prism/src/prism.c:19902:29
    #11 0xaaaae140ed90 in parse_expression /prism/src/prism.c:21537:23
    #12 0xaaaae140b804 in parse_statements /prism/src/prism.c:13163:27
    #13 0xaaaae13ce274 in parse_program /prism/src/prism.c:21810:40
    #14 0xaaaae13ce274 in pm_parse /prism/src/prism.c:22242:12
    #15 0xaaaae14e2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #16 0xaaaae1514320 in harness /prism/fuzz/parse.c:9:5
    #17 0xaaaae15144c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #18 0xaaaae13a6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #19 0xaaaae13a5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #20 0xaaaae13a5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #21 0xffff900973fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #22 0xffff900974d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #23 0xaaaae12cf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Direct leak of 3 byte(s) in 1 object(s) allocated from:
    #0 0xaaaae136daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaae1501518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaae13ec510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaae13ec510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaae1486144 in parse_string_part /prism/src/prism.c:15452:13
    #5 0xaaaae14277a0 in parse_expression_prefix /prism/src/prism.c:19902:29
    #6 0xaaaae140ed90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaae140b804 in parse_statements /prism/src/prism.c:13163:27
    #8 0xaaaae13ce274 in parse_program /prism/src/prism.c:21810:40
    #9 0xaaaae13ce274 in pm_parse /prism/src/prism.c:22242:12
    #10 0xaaaae14e2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #11 0xaaaae1514320 in harness /prism/fuzz/parse.c:9:5
    #12 0xaaaae15144c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #13 0xaaaae13a6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #14 0xaaaae13a5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #15 0xaaaae13a5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #16 0xffff900973fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #17 0xffff900974d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #18 0xaaaae12cf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 15 byte(s) leaked in 2 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
".`?\\u{cde aAcde "
*/
static const uint8_t input[] = {0x2e, 0x60, 0x3f, 0x5c, 0x75, 0x7b, 0x63, 0x64,
                                0x65, 0x20, 0x61, 0x41, 0x63, 0x64, 0x65, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
