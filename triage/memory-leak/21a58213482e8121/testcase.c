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
==46047==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 128 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad7a3de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad7bd243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad7bd243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad7bd243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaad7aae414 in pm_token_buffer_escape /prism/src/prism.c:9619:5
    #5 0xaaaad7aae414 in parser_lex /prism/src/prism.c:11685:25
    #6 0xaaaad7b9b4e8 in parse_operator_symbol /prism/src/prism.c:15483:5
    #7 0xaaaad7b9b4e8 in parse_symbol /prism/src/prism.c:15505:24
    #8 0xaaaad7ae8864 in parse_expression_prefix /prism/src/prism.c:20112:20
    #9 0xaaaad7aded90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaad7adb804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaad7afabf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #12 0xaaaad7aded90 in parse_expression /prism/src/prism.c:21537:23
    #13 0xaaaad7adb804 in parse_statements /prism/src/prism.c:13163:27
    #14 0xaaaad7a9e274 in parse_program /prism/src/prism.c:21810:40
    #15 0xaaaad7a9e274 in pm_parse /prism/src/prism.c:22242:12
    #16 0xaaaad7bb2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #17 0xaaaad7be4320 in harness /prism/fuzz/parse.c:9:5
    #18 0xaaaad7be44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #19 0xaaaad7a76034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #20 0xaaaad7a75ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #21 0xaaaad7a75988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #22 0xffffa77173fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #23 0xffffa77174d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #24 0xaaaad799f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 128 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"def:`000000000000000000000000000000000\\\x1C"
*/
static const uint8_t input[] = {0x64, 0x65, 0x66, 0x3a, 0x60, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x1c};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
