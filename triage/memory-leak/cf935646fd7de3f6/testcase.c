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
==80342==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaac08dde98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaac0a7243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaac0a7243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaac0a7243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaac094d798 in parser_lex /prism/src/prism.c:11457:33
    #5 0xaaaac09e1058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #6 0xaaaac09e2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #7 0xaaaac09d9114 in parse_pattern /prism/src/prism.c
    #8 0xaaaac09ea740 in parse_pattern_constant_path /prism/src/prism.c:16175:21
    #9 0xaaaac09dfe48 in parse_pattern_primitive /prism/src/prism.c:16797:20
    #10 0xaaaac09e2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #11 0xaaaac09d9114 in parse_pattern /prism/src/prism.c
    #12 0xaaaac09e0840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #13 0xaaaac09e2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #14 0xaaaac09d9114 in parse_pattern /prism/src/prism.c
    #15 0xaaaac09a8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #16 0xaaaac097f204 in parse_expression /prism/src/prism.c:21589:16
    #17 0xaaaac0990a04 in parse_expression_prefix /prism/src/prism.c:17526:36
    #18 0xaaaac097ed90 in parse_expression /prism/src/prism.c:21537:23
    #19 0xaaaac0990a04 in parse_expression_prefix /prism/src/prism.c:17526:36
    #20 0xaaaac097ed90 in parse_expression /prism/src/prism.c:21537:23
    #21 0xaaaac0990a04 in parse_expression_prefix /prism/src/prism.c:17526:36
    #22 0xaaaac097ed90 in parse_expression /prism/src/prism.c:21537:23
    #23 0xaaaac0990a04 in parse_expression_prefix /prism/src/prism.c:17526:36
    #24 0xaaaac097ed90 in parse_expression /prism/src/prism.c:21537:23
    #25 0xaaaac097b804 in parse_statements /prism/src/prism.c:13163:27
    #26 0xaaaac093e274 in parse_program /prism/src/prism.c:21810:40
    #27 0xaaaac093e274 in pm_parse /prism/src/prism.c:22242:12
    #28 0xaaaac0a52800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #29 0xaaaac0a84320 in harness /prism/fuzz/parse.c:9:5
    #30 0xaaaac0a844c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #31 0xaaaac0916034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #32 0xaaaac0915ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in{/0\\u{                             "
*/
static const uint8_t input[] = {0x31, 0x69, 0x6e, 0x7b, 0x2f, 0x30, 0x5c, 0x75,
                                0x7b, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
