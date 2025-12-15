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
==16629==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 6 byte(s) in 2 object(s) allocated from:
    #0 0xaaaaccf1daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaacd0b1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaaccf9c510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaaccf9c510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaacd01fc68 in parse_pattern_primitive /prism/src/prism.c:16615:13
    #5 0xaaaacd022ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #6 0xaaaacd0194a0 in parse_pattern /prism/src/prism.c:17023:24
    #7 0xaaaaccfe8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #8 0xaaaaccfbf204 in parse_expression /prism/src/prism.c:21589:16
    #9 0xaaaaccfbb804 in parse_statements /prism/src/prism.c:13163:27
    #10 0xaaaaccf7e274 in parse_program /prism/src/prism.c:21810:40
    #11 0xaaaaccf7e274 in pm_parse /prism/src/prism.c:22242:12
    #12 0xaaaacd092800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #13 0xaaaacd0c4320 in harness /prism/fuzz/parse.c:9:5
    #14 0xaaaacd0c44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #15 0xaaaaccf56034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #16 0xaaaaccf55ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #17 0xaaaaccf55988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #18 0xffff9fe573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #19 0xffff9fe574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #20 0xaaaacce7f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 6 byte(s) leaked in 2 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in,{?\\ x in,{?\\ "
*/
static const uint8_t input[] = {0x31, 0x69, 0x6e, 0x2c, 0x7b, 0x3f,
                                0x5c, 0x20, 0x78, 0x20, 0x69, 0x6e,
                                0x2c, 0x7b, 0x3f, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
