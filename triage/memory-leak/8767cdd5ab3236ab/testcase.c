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
==30061==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaac6d8de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaac6f227a0 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaac6f227a0 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaac6f227a0 in pm_buffer_append_byte /prism/src/util/pm_buffer.c:137:5
    #4 0xaaaac6dfe784 in parser_lex /prism/src/prism.c:11731:37
    #5 0xaaaac6e49344 in parse_expression_prefix /prism/src/prism.c:18645:21
    #6 0xaaaac6e2ed90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaac6e2b804 in parse_statements /prism/src/prism.c:13163:27
    #8 0xaaaac6e4abf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #9 0xaaaac6e2ed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaac6e2b804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaac6dee274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaac6dee274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaac6f02800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaac6f34320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaac6f344c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaac6dc6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaac6dc5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaac6dc5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffff8b2273fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffff8b2274d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaac6cef22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"def s def`00000000000000000000000000000000\\h"
*/
static const uint8_t input[] = {
    0x64, 0x65, 0x66, 0x20, 0x73, 0x20, 0x64, 0x65, 0x66, 0x60, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x68};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
