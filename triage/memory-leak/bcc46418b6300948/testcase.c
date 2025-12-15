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
==56241==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaacf3ade98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaacf543ba4 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaacf543ba4 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaacf543ba4 in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaacf543ba4 in pm_buffer_append_unicode_codepoint /prism/src/util/pm_buffer.c:189:9
    #5 0xaaaacf513730 in escape_write_unicode /prism/src/prism.c:8659:10
    #6 0xaaaacf513730 in escape_read /prism/src/prism.c:8927:21
    #7 0xaaaacf41e784 in parser_lex /prism/src/prism.c:11731:37
    #8 0xaaaacf4f3a50 in parse_operator_symbol /prism/src/prism.c:15483:5
    #9 0xaaaacf4f3a50 in parse_alias_argument /prism/src/prism.c:15678:20
    #10 0xaaaacf45c604 in parse_expression_prefix /prism/src/prism.c:18117:35
    #11 0xaaaacf44ed90 in parse_expression /prism/src/prism.c:21537:23
    #12 0xaaaacf44b804 in parse_statements /prism/src/prism.c:13163:27
    #13 0xaaaacf466c24 in parse_expression_prefix /prism/src/prism.c:20071:28
    #14 0xaaaacf44ed90 in parse_expression /prism/src/prism.c:21537:23
    #15 0xaaaacf4affb8 in parse_pattern_primitive /prism/src/prism.c:16680:31
    #16 0xaaaacf4b2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #17 0xaaaacf4a94a0 in parse_pattern /prism/src/prism.c:17023:24
    #18 0xaaaacf4b0840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #19 0xaaaacf4b3318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #20 0xaaaacf4a9114 in parse_pattern /prism/src/prism.c
    #21 0xaaaacf4b0840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #22 0xaaaacf4b3318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #23 0xaaaacf4a9114 in parse_pattern /prism/src/prism.c
    #24 0xaaaacf4b0840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #25 0xaaaacf4b3318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #26 0xaaaacf4a9114 in parse_pattern /prism/src/prism.c
    #27 0xaaaacf4796f4 in parse_expression_infix /prism/src/prism.c:21492:34
    #28 0xaaaacf44f204 in parse_expression /prism/src/prism.c:21589:16
    #29 0xaaaacf44b804 in parse_statements /prism/src/prism.c:13163:27
    #30 0xaaaacf40e274 in parse_program /prism/src/prism.c:21810:40
    #31 0xaaaacf40e274 in pm_parse /prism/src/prism.c:22242:12
    #32 0xaaaacf522800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #33 0xaaaacf554320 in harness /prism/fuzz/parse.c:9:5
    #34 0xaaaacf5544c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #35 0xaaaacf3e6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"alias$ `0000000000000000000000000000000\\u{fa  "
*/
static const uint8_t input[] = {
    0x61, 0x6c, 0x69, 0x61, 0x73, 0x24, 0x20, 0x60, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5c, 0x75, 0x7b, 0x66, 0x61, 0x20, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
