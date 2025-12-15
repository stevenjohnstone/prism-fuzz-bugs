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
==59849==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaaadfcde98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaaae16243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaaae16243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaaae16243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaaae13c850 in pm_regexp_token_buffer_flush /prism/src/prism.c:9591:9
    #5 0xaaaaae040178 in parser_lex /prism/src/prism.c:11339:25
    #6 0xaaaaae0d1058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaaae0d2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #8 0xaaaaae0c9114 in parse_pattern /prism/src/prism.c
    #9 0xaaaaae0cdc2c in parse_pattern_hash /prism/src/prism.c:16435:29
    #10 0xaaaaae0c8f0c in parse_pattern /prism/src/prism.c:16938:20
    #11 0xaaaaae098684 in parse_expression_infix /prism/src/prism.c:21475:34
    #12 0xaaaaae06f204 in parse_expression /prism/src/prism.c:21589:16
    #13 0xaaaaae06b804 in parse_statements /prism/src/prism.c:13163:27
    #14 0xaaaaae0c69c0 in parse_block /prism/src/prism.c:14736:26
    #15 0xaaaaae0b8970 in parse_arguments_list /prism/src/prism.c:14822:21
    #16 0xaaaaae07ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #17 0xaaaaae06ed90 in parse_expression /prism/src/prism.c:21537:23
    #18 0xaaaaae099b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #19 0xaaaaae06f204 in parse_expression /prism/src/prism.c:21589:16
    #20 0xaaaaae0a0db8 in parse_value_expression /prism/src/prism.c:12430:23
    #21 0xaaaaae0a0db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #22 0xaaaaae0a0db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #23 0xaaaaae09cc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #24 0xaaaaae06f204 in parse_expression /prism/src/prism.c:21589:16
    #25 0xaaaaae099b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #26 0xaaaaae06f204 in parse_expression /prism/src/prism.c:21589:16
    #27 0xaaaaae080a04 in parse_expression_prefix /prism/src/prism.c:17526:36
    #28 0xaaaaae06ed90 in parse_expression /prism/src/prism.c:21537:23
    #29 0xaaaaae06b804 in parse_statements /prism/src/prism.c:13163:27
    #30 0xaaaaae02e274 in parse_program /prism/src/prism.c:21810:40
    #31 0xaaaaae02e274 in pm_parse /prism/src/prism.c:22242:12
    #32 0xaaaaae142800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #33 0xaaaaae174320 in harness /prism/fuzz/parse.c:9:5
    #34 0xaaaaae1744c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"~in {/000000\\0000000000/"
*/
static const uint8_t input[] = {0x7e, 0x69, 0x6e, 0x20, 0x7b, 0x2f, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x5c, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x2f};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
