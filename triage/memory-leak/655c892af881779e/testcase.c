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
==37231==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 12 byte(s) in 4 object(s) allocated from:
    #0 0xaaaacc8ddaa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaacca71518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaacc95c510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaacc95c510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaacc9863dc in parse_expression_prefix /prism/src/prism.c:19525:25
    #5 0xaaaacc97ed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaacc9d0954 in parse_value_expression /prism/src/prism.c:12430:23
    #7 0xaaaacc9d0954 in parse_arguments /prism/src/prism.c:13562:32
    #8 0xaaaacc9aab04 in parse_expression_infix /prism/src/prism.c:21426:17
    #9 0xaaaacc97f204 in parse_expression /prism/src/prism.c:21589:16
    #10 0xaaaacc97b804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaacc996c24 in parse_expression_prefix /prism/src/prism.c:20071:28
    #12 0xaaaacc97ed90 in parse_expression /prism/src/prism.c:21537:23
    #13 0xaaaacca2e384 in parse_value_expression /prism/src/prism.c:12430:23
    #14 0xaaaacca2e384 in parse_predicate /prism/src/prism.c:15088:28
    #15 0xaaaacca2e384 in parse_conditional /prism/src/prism.c:15114:28
    #16 0xaaaacc98cd60 in parse_expression_prefix /prism/src/prism.c
    #17 0xaaaacc97ed90 in parse_expression /prism/src/prism.c:21537:23
    #18 0xaaaacc98c844 in parse_expression_prefix /prism/src/prism.c:18555:40
    #19 0xaaaacc97ed90 in parse_expression /prism/src/prism.c:21537:23
    #20 0xaaaacc9b0db8 in parse_value_expression /prism/src/prism.c:12430:23
    #21 0xaaaacc9b0db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #22 0xaaaacc9b0db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #23 0xaaaacc9acc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #24 0xaaaacc97f204 in parse_expression /prism/src/prism.c:21589:16
    #25 0xaaaacc97b804 in parse_statements /prism/src/prism.c:13163:27
    #26 0xaaaacc93e274 in parse_program /prism/src/prism.c:21810:40
    #27 0xaaaacc93e274 in pm_parse /prism/src/prism.c:22242:12
    #28 0xaaaacca52800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #29 0xaaaacca84320 in harness /prism/fuzz/parse.c:9:5
    #30 0xaaaacca844c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #31 0xaaaacc916034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #32 0xaaaacc915ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #33 0xaaaacc915988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #34 0xffffa28673fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #35 0xffffa28674d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #36 0xaaaacc83f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 12 byte(s) leaked in 4 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"if- %I \#{-;?\\ :?\\ :?\\ :?\\"
*/
static const uint8_t input[] = {0x69, 0x66, 0x2d, 0x20, 0x25, 0x49, 0x20,
                                0x23, 0x7b, 0x2d, 0x3b, 0x3f, 0x5c, 0x20,
                                0x3a, 0x3f, 0x5c, 0x20, 0x3a, 0x3f, 0x5c,
                                0x20, 0x3a, 0x3f, 0x5c};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
