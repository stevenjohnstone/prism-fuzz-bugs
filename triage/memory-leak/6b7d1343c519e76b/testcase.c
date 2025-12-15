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
==1977==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaac301de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaac31b243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaac31b243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaac31b243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaac308e414 in pm_token_buffer_escape /prism/src/prism.c:9619:5
    #5 0xaaaac308e414 in parser_lex /prism/src/prism.c:11685:25
    #6 0xaaaac30ed20c in parse_expression_infix /prism/src/prism.c:21234:21
    #7 0xaaaac30bf204 in parse_expression /prism/src/prism.c:21589:16
    #8 0xaaaac30bb804 in parse_statements /prism/src/prism.c:13163:27
    #9 0xaaaac30dabf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #10 0xaaaac30bed90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaac30bb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaac307e274 in parse_program /prism/src/prism.c:21810:40
    #13 0xaaaac307e274 in pm_parse /prism/src/prism.c:22242:12
    #14 0xaaaac3192800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #15 0xaaaac31c4320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaac31c44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaac3056034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaac3055ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaac3055988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffffb1af73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffffb1af74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaac2f7f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":.`00000000000000000\\e"
*/
static const uint8_t input[] = {0x3a, 0x2e, 0x60, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x5c, 0x65};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
