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
==19691==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaaac29daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaaac431518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaaac30e3b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaaac30e3b8 in parser_lex /prism/src/prism.c:11685:25
    #4 0xaaaaac3e3a50 in parse_operator_symbol /prism/src/prism.c:15483:5
    #5 0xaaaaac3e3a50 in parse_alias_argument /prism/src/prism.c:15678:20
    #6 0xaaaaac34c604 in parse_expression_prefix /prism/src/prism.c:18117:35
    #7 0xaaaaac33ed90 in parse_expression /prism/src/prism.c:21537:23
    #8 0xaaaaac34cc34 in parse_expression_prefix /prism/src/prism.c:19952:35
    #9 0xaaaaac33ed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaaac369b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #11 0xaaaaac33f204 in parse_expression /prism/src/prism.c:21589:16
    #12 0xaaaaac33b804 in parse_statements /prism/src/prism.c:13163:27
    #13 0xaaaaac2fe274 in parse_program /prism/src/prism.c:21810:40
    #14 0xaaaaac2fe274 in pm_parse /prism/src/prism.c:22242:12
    #15 0xaaaaac412800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #16 0xaaaaac444320 in harness /prism/fuzz/parse.c:9:5
    #17 0xaaaaac4444c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #18 0xaaaaac2d6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #19 0xaaaaac2d5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #20 0xaaaaac2d5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #21 0xffffbef573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #22 0xffffbef574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #23 0xaaaaac1ff22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"alias$ `\\-"
*/
static const uint8_t input[] = {0x61, 0x6c, 0x69, 0x61, 0x73,
                                0x24, 0x20, 0x60, 0x5c, 0x2d};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
