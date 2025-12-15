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
==38048==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaabc99daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaabcb31518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaabca12a14 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaabca12a14 in parser_lex /prism/src/prism.c:11907:25
    #4 0xaaaabca3bb2c in parse_statements /prism/src/prism.c:13204:13
    #5 0xaaaabc9fe274 in parse_program /prism/src/prism.c:21810:40
    #6 0xaaaabc9fe274 in pm_parse /prism/src/prism.c:22242:12
    #7 0xaaaabcb12800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #8 0xaaaabcb44320 in harness /prism/fuzz/parse.c:9:5
    #9 0xaaaabcb444c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #10 0xaaaabc9d6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #11 0xaaaabc9d5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #12 0xaaaabc9d5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #13 0xffff846373fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #14 0xffff846374d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #15 0xaaaabc8ff22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"5in   {<<~0\n\n\r\n\n"
*/
static const uint8_t input[] = {0x35, 0x69, 0x6e, 0x20, 0x20, 0x20, 0x7b, 0x3c,
                                0x3c, 0x7e, 0x30, 0x0a, 0x0a, 0x0d, 0x0a, 0x0a};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
