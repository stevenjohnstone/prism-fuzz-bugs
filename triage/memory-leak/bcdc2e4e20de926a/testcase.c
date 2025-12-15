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
==33634==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab9b7daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab9d11518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaab9bee5b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaab9bee5b8 in parser_lex /prism/src/prism.c:11654:25
    #4 0xaaaab9cc3a50 in parse_operator_symbol /prism/src/prism.c:15483:5
    #5 0xaaaab9cc3a50 in parse_alias_argument /prism/src/prism.c:15678:20
    #6 0xaaaab9c2c604 in parse_expression_prefix /prism/src/prism.c:18117:35
    #7 0xaaaab9c1ed90 in parse_expression /prism/src/prism.c:21537:23
    #8 0xaaaab9c1b804 in parse_statements /prism/src/prism.c:13163:27
    #9 0xaaaab9bde274 in parse_program /prism/src/prism.c:21810:40
    #10 0xaaaab9bde274 in pm_parse /prism/src/prism.c:22242:12
    #11 0xaaaab9cf2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #12 0xaaaab9d24320 in harness /prism/fuzz/parse.c:9:5
    #13 0xaaaab9d244c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #14 0xaaaab9bb6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #15 0xaaaab9bb5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #16 0xaaaab9bb5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #17 0xffffa5e273fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #18 0xffffa5e274d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #19 0xaaaab9adf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"alias$ `\r\n"
*/
static const uint8_t input[] = {0x61, 0x6c, 0x69, 0x61, 0x73,
                                0x24, 0x20, 0x60, 0x0d, 0x0a};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
