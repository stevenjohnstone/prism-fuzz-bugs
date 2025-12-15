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
==34334==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad7dbde98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad7f527a0 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad7f527a0 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad7f527a0 in pm_buffer_append_byte /prism/src/util/pm_buffer.c:137:5
    #4 0xaaaad7e3270c in parser_lex /prism/src/prism.c:12059:37
    #5 0xaaaad7e5bb2c in parse_statements /prism/src/prism.c:13204:13
    #6 0xaaaad7ed61ec in parse_string_part /prism/src/prism.c:15372:30
    #7 0xaaaad7ed0c98 in parse_strings /prism/src/prism.c:16036:33
    #8 0xaaaad7e6a2d8 in parse_expression_prefix /prism/src/prism.c:20107:20
    #9 0xaaaad7e5ed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaad7eb0954 in parse_value_expression /prism/src/prism.c:12430:23
    #11 0xaaaad7eb0954 in parse_arguments /prism/src/prism.c:13562:32
    #12 0xaaaad7ea90b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #13 0xaaaad7e6ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #14 0xaaaad7e5ed90 in parse_expression /prism/src/prism.c:21537:23
    #15 0xaaaad7e5b804 in parse_statements /prism/src/prism.c:13163:27
    #16 0xaaaad7e1e274 in parse_program /prism/src/prism.c:21810:40
    #17 0xaaaad7e1e274 in pm_parse /prism/src/prism.c:22242:12
    #18 0xaaaad7f32800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #19 0xaaaad7f64320 in harness /prism/fuzz/parse.c:9:5
    #20 0xaaaad7f644c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #21 0xaaaad7df6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #22 0xaaaad7df5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #23 0xaaaad7df5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #24 0xffff90c573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #25 0xffff90c574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #26 0xaaaad7d1f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"5in   {<<~0\n                \\<"
*/
static const uint8_t input[] = {0x35, 0x69, 0x6e, 0x20, 0x20, 0x20, 0x7b, 0x3c,
                                0x3c, 0x7e, 0x30, 0x0a, 0x20, 0x20, 0x20, 0x20,
                                0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                                0x20, 0x20, 0x20, 0x20, 0x5c, 0x3c};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
