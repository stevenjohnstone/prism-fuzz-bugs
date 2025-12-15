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
==32607==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad161de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad17b27a0 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad17b27a0 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad17b27a0 in pm_buffer_append_byte /prism/src/util/pm_buffer.c:137:5
    #4 0xaaaad168fb90 in parser_lex /prism/src/prism.c:11224:33
    #5 0xaaaad16bbb2c in parse_statements /prism/src/prism.c:13204:13
    #6 0xaaaad167e274 in parse_program /prism/src/prism.c:21810:40
    #7 0xaaaad167e274 in pm_parse /prism/src/prism.c:22242:12
    #8 0xaaaad1792800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #9 0xaaaad17c4320 in harness /prism/fuzz/parse.c:9:5
    #10 0xaaaad17c44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #11 0xaaaad1656034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #12 0xaaaad1655ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #13 0xaaaad1655988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #14 0xffff91c573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #15 0xffff91c574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #16 0xaaaad157f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"A in{%W 00000000\x8F\x00000000\\J "
*/
static const uint8_t input[] = {0x41, 0x20, 0x69, 0x6e, 0x7b, 0x25, 0x57,
                                0x20, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x8f, 0x00, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x5c, 0x4a, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
