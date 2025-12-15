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
==1931==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad748daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad7621518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaad74fe3b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaad74fe3b8 in parser_lex /prism/src/prism.c:11685:25
    #4 0xaaaad752bb2c in parse_statements /prism/src/prism.c:13204:13
    #5 0xaaaad754abf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #6 0xaaaad752ed90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaad752b804 in parse_statements /prism/src/prism.c:13163:27
    #8 0xaaaad754abf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #9 0xaaaad752ed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaad7545c24 in parse_expression_prefix /prism/src/prism.c:17640:35
    #11 0xaaaad752ed90 in parse_expression /prism/src/prism.c:21537:23
    #12 0xaaaad752b804 in parse_statements /prism/src/prism.c:13163:27
    #13 0xaaaad74ee274 in parse_program /prism/src/prism.c:21810:40
    #14 0xaaaad74ee274 in pm_parse /prism/src/prism.c:22242:12
    #15 0xaaaad7602800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #16 0xaaaad7634320 in harness /prism/fuzz/parse.c:9:5
    #17 0xaaaad76344c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #18 0xaaaad74c6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #19 0xaaaad74c5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #20 0xaaaad74c5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #21 0xffffb8c673fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #22 0xffffb8c674d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #23 0xaaaad73ef22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"def e def`\#{}\\ "
*/
static const uint8_t input[] = {0x64, 0x65, 0x66, 0x20, 0x65, 0x20, 0x64, 0x65,
                                0x66, 0x60, 0x23, 0x7b, 0x7d, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
