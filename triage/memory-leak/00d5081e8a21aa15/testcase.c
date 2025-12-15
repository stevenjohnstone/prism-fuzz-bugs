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
==64740==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 6 byte(s) in 2 object(s) allocated from:
    #0 0xaaaac614daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaac62e1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaac61cc510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaac61cc510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaac6266144 in parse_string_part /prism/src/prism.c:15452:13
    #5 0xaaaac625f1b8 in parse_strings /prism/src/prism.c:16062:29
    #6 0xaaaac61fa2d8 in parse_expression_prefix /prism/src/prism.c:20107:20
    #7 0xaaaac61eed90 in parse_expression /prism/src/prism.c:21537:23
    #8 0xaaaac6205c24 in parse_expression_prefix /prism/src/prism.c:17640:35
    #9 0xaaaac61eed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaac61eb804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaac61ae274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaac61ae274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaac62c2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaac62f4320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaac62f44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaac6186034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaac6185ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaac6185988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffff8eb973fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffff8eb974d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaac60af22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 6 byte(s) leaked in 2 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"(% \#{)?\\ ,?\\"
*/
static const uint8_t input[] = {0x28, 0x25, 0x20, 0x23, 0x7b, 0x29,
                                0x3f, 0x5c, 0x20, 0x2c, 0x3f, 0x5c};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
