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
==44337==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 3 byte(s) in 1 object(s) allocated from:
    #0 0xaaaade0bdaa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaade251518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaade13c510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaade13c510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaade165918 in parse_expression_prefix /prism/src/prism.c:17883:13
    #5 0xaaaade15ed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaade1898e8 in parse_expression_infix /prism/src/prism.c:21185:35
    #7 0xaaaade15f204 in parse_expression /prism/src/prism.c:21589:16
    #8 0xaaaade188848 in parse_expression_infix /prism/src/prism.c:21067:35
    #9 0xaaaade15f204 in parse_expression /prism/src/prism.c:21589:16
    #10 0xaaaade15b804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaade11e274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaade11e274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaade232800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaade264320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaade2644c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaade0f6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaade0f5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaade0f5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffff99c073fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffff99c074d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaade01f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 3 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"(?<while)   >p ?\\u"
*/
static const uint8_t input[] = {0x28, 0x3f, 0x3c, 0x77, 0x68, 0x69,
                                0x6c, 0x65, 0x29, 0x20, 0x20, 0x20,
                                0x3e, 0x70, 0x20, 0x3f, 0x5c, 0x75};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
