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
==53240==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaabe52de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaabe6c1c58 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaabe6c1c58 in pm_buffer_append_format /prism/src/util/pm_buffer.c:107:9
    #3 0xaaaabe692134 in escape_write_byte /prism/src/prism.c:8702:9
    #4 0xaaaabe692134 in escape_read /prism/src/prism.c:8785:13
    #5 0xaaaabe59d798 in parser_lex /prism/src/prism.c:11457:33
    #6 0xaaaabe631058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaabe632ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #8 0xaaaabe629114 in parse_pattern /prism/src/prism.c
    #9 0xaaaabe5f96f4 in parse_expression_infix /prism/src/prism.c:21492:34
    #10 0xaaaabe5cf204 in parse_expression /prism/src/prism.c:21589:16
    #11 0xaaaabe5cb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaabe5e6c24 in parse_expression_prefix /prism/src/prism.c:20071:28
    #13 0xaaaabe5ced90 in parse_expression /prism/src/prism.c:21537:23
    #14 0xaaaabe62ffb8 in parse_pattern_primitive /prism/src/prism.c:16680:31
    #15 0xaaaabe632ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #16 0xaaaabe629114 in parse_pattern /prism/src/prism.c
    #17 0xaaaabe63a740 in parse_pattern_constant_path /prism/src/prism.c:16175:21
    #18 0xaaaabe62fe48 in parse_pattern_primitive /prism/src/prism.c:16797:20
    #19 0xaaaabe633318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #20 0xaaaabe629114 in parse_pattern /prism/src/prism.c
    #21 0xaaaabe5f96f4 in parse_expression_infix /prism/src/prism.c:21492:34
    #22 0xaaaabe5cf204 in parse_expression /prism/src/prism.c:21589:16
    #23 0xaaaabe5cb804 in parse_statements /prism/src/prism.c:13163:27
    #24 0xaaaabe58e274 in parse_program /prism/src/prism.c:21810:40
    #25 0xaaaabe58e274 in pm_parse /prism/src/prism.c:22242:12
    #26 0xaaaabe6a2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #27 0xaaaabe6d4320 in harness /prism/fuzz/parse.c:9:5
    #28 0xaaaabe6d44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #29 0xaaaabe566034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #30 0xaaaabe565ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #31 0xaaaabe565988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #32 0xffffb0e273fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"f=>{/000000000000\\M-\\e"
*/
static const uint8_t input[] = {0x66, 0x3d, 0x3e, 0x7b, 0x2f, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x5c, 0x4d, 0x2d, 0x5c, 0x65};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
