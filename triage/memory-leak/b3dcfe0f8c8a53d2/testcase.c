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
==30835==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab747de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab7611c58 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaab7611c58 in pm_buffer_append_format /prism/src/util/pm_buffer.c:107:9
    #3 0xaaaab75eef18 in escape_write_byte /prism/src/prism.c:8702:9
    #4 0xaaaab74ed798 in parser_lex /prism/src/prism.c:11457:33
    #5 0xaaaab7581058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #6 0xaaaab7582ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #7 0xaaaab7579114 in parse_pattern /prism/src/prism.c
    #8 0xaaaab7548684 in parse_expression_infix /prism/src/prism.c:21475:34
    #9 0xaaaab751f204 in parse_expression /prism/src/prism.c:21589:16
    #10 0xaaaab751b804 in parse_statements /prism/src/prism.c:13163:27
    #11 0xaaaab74de274 in parse_program /prism/src/prism.c:21810:40
    #12 0xaaaab74de274 in pm_parse /prism/src/prism.c:22242:12
    #13 0xaaaab75f2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #14 0xaaaab7624320 in harness /prism/fuzz/parse.c:9:5
    #15 0xaaaab76244c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #16 0xaaaab74b6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #17 0xaaaab74b5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #18 0xaaaab74b5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #19 0xffffa2c173fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #20 0xffffa2c174d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #21 0xaaaab73df22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"-in{/0000000000000000000000000000\\M- "
*/
static const uint8_t input[] = {0x2d, 0x69, 0x6e, 0x7b, 0x2f, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x5c, 0x4d, 0x2d, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
