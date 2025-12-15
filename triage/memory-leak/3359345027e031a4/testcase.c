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
==3459==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad6ffde98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad719243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad719243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad719243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaad716d60c in pm_regexp_token_buffer_push_escaped /prism/src/prism.c:9534:5
    #5 0xaaaad706d490 in parser_lex /prism/src/prism.c:11481:33
    #6 0xaaaad7101058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaad7102ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #8 0xaaaad70f9114 in parse_pattern /prism/src/prism.c
    #9 0xaaaad70c8684 in parse_expression_infix /prism/src/prism.c:21475:34
    #10 0xaaaad709f204 in parse_expression /prism/src/prism.c:21589:16
    #11 0xaaaad70b0a04 in parse_expression_prefix /prism/src/prism.c:17526:36
    #12 0xaaaad709ed90 in parse_expression /prism/src/prism.c:21537:23
    #13 0xaaaad70ac844 in parse_expression_prefix /prism/src/prism.c:18555:40
    #14 0xaaaad709ed90 in parse_expression /prism/src/prism.c:21537:23
    #15 0xaaaad70d0db8 in parse_value_expression /prism/src/prism.c:12430:23
    #16 0xaaaad70d0db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #17 0xaaaad70d0db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #18 0xaaaad70ccc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #19 0xaaaad709f204 in parse_expression /prism/src/prism.c:21589:16
    #20 0xaaaad70f0954 in parse_value_expression /prism/src/prism.c:12430:23
    #21 0xaaaad70f0954 in parse_arguments /prism/src/prism.c:13562:32
    #22 0xaaaad70e8734 in parse_arguments_list /prism/src/prism.c:14784:13
    #23 0xaaaad70aef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #24 0xaaaad709ed90 in parse_expression /prism/src/prism.c:21537:23
    #25 0xaaaad70d98d4 in parse_value_expression /prism/src/prism.c:12430:23
    #26 0xaaaad70d98d4 in parse_assignment_value /prism/src/prism.c:20156:24
    #27 0xaaaad70cb9fc in parse_expression_infix /prism/src/prism.c:21026:40
    #28 0xaaaad709f204 in parse_expression /prism/src/prism.c:21589:16
    #29 0xaaaad709b804 in parse_statements /prism/src/prism.c:13163:27
    #30 0xaaaad705e274 in parse_program /prism/src/prism.c:21810:40
    #31 0xaaaad705e274 in pm_parse /prism/src/prism.c:22242:12
    #32 0xaaaad7172800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #33 0xaaaad71a4320 in harness /prism/fuzz/parse.c:9:5
    #34 0xaaaad71a44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #35 0xaaaad7036034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #36 0xaaaad7035ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"a in{/000000000000000\\0"
*/
static const uint8_t input[] = {0x61, 0x20, 0x69, 0x6e, 0x7b, 0x2f, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
