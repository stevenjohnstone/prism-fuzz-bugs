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
==59478==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaaaed8daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaaaef21518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaaaedff93c in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaaaedff93c in parser_lex /prism/src/prism.c:11183:21
    #4 0xaaaaaee91058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #5 0xaaaaaee92ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #6 0xaaaaaee89114 in parse_pattern /prism/src/prism.c
    #7 0xaaaaaee8dc2c in parse_pattern_hash /prism/src/prism.c:16435:29
    #8 0xaaaaaee88f0c in parse_pattern /prism/src/prism.c:16938:20
    #9 0xaaaaaee58684 in parse_expression_infix /prism/src/prism.c:21475:34
    #10 0xaaaaaee2f204 in parse_expression /prism/src/prism.c:21589:16
    #11 0xaaaaaee2b804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaaaee869c0 in parse_block /prism/src/prism.c:14736:26
    #13 0xaaaaaee78970 in parse_arguments_list /prism/src/prism.c:14822:21
    #14 0xaaaaaee3ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #15 0xaaaaaee2ed90 in parse_expression /prism/src/prism.c:21537:23
    #16 0xaaaaaee59b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #17 0xaaaaaee2f204 in parse_expression /prism/src/prism.c:21589:16
    #18 0xaaaaaee60db8 in parse_value_expression /prism/src/prism.c:12430:23
    #19 0xaaaaaee60db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #20 0xaaaaaee60db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #21 0xaaaaaee5cc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #22 0xaaaaaee2f204 in parse_expression /prism/src/prism.c:21589:16
    #23 0xaaaaaee59b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #24 0xaaaaaee2f204 in parse_expression /prism/src/prism.c:21589:16
    #25 0xaaaaaee40a04 in parse_expression_prefix /prism/src/prism.c:17526:36
    #26 0xaaaaaee2ed90 in parse_expression /prism/src/prism.c:21537:23
    #27 0xaaaaaee2b804 in parse_statements /prism/src/prism.c:13163:27
    #28 0xaaaaaedee274 in parse_program /prism/src/prism.c:21810:40
    #29 0xaaaaaedee274 in pm_parse /prism/src/prism.c:22242:12
    #30 0xaaaaaef02800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #31 0xaaaaaef34320 in harness /prism/fuzz/parse.c:9:5
    #32 0xaaaaaef344c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #33 0xaaaaaedc6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"5in{%I \\ "
*/
static const uint8_t input[] = {0x35, 0x69, 0x6e, 0x7b, 0x25,
                                0x49, 0x20, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
