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
==99689==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 4 object(s) allocated from:
    #0 0xaaaaae45daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaaae5f1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaaae4cf93c in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaaae4cf93c in parser_lex /prism/src/prism.c:11183:21
    #4 0xaaaaae4fbb2c in parse_statements /prism/src/prism.c:13204:13
    #5 0xaaaaae5151b4 in parse_expression_prefix /prism/src/prism.c:18316:38
    #6 0xaaaaae4fed90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaaae4fb804 in parse_statements /prism/src/prism.c:13163:27
    #8 0xaaaaae4be274 in parse_program /prism/src/prism.c:21810:40
    #9 0xaaaaae4be274 in pm_parse /prism/src/prism.c:22242:12
    #10 0xaaaaae5d2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #11 0xaaaaae604320 in harness /prism/fuzz/parse.c:9:5
    #12 0xaaaaae6044c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #13 0xaaaaae496034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #14 0xaaaaae495ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #15 0xaaaaae495988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #16 0xffff8ecd73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #17 0xffff8ecd74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #18 0xaaaaae3bf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 4 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"case in{%I  \\  \\  \\  \\ "
*/
static const uint8_t input[] = {0x63, 0x61, 0x73, 0x65, 0x20, 0x69, 0x6e, 0x7b,
                                0x25, 0x49, 0x20, 0x20, 0x5c, 0x20, 0x20, 0x5c,
                                0x20, 0x20, 0x5c, 0x20, 0x20, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
