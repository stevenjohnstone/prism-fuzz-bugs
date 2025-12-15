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
==10066==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaabe75de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaabe8f1c58 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaabe8f1c58 in pm_buffer_append_format /prism/src/util/pm_buffer.c:107:9
    #3 0xaaaabe8c226c in escape_write_byte /prism/src/prism.c:8702:9
    #4 0xaaaabe8c226c in escape_read /prism/src/prism.c:8770:13
    #5 0xaaaabe7cd798 in parser_lex /prism/src/prism.c:11457:33
    #6 0xaaaabe861058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaabe862ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #8 0xaaaabe859114 in parse_pattern /prism/src/prism.c
    #9 0xaaaabe860840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #10 0xaaaabe862ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #11 0xaaaabe859114 in parse_pattern /prism/src/prism.c
    #12 0xaaaabe8296f4 in parse_expression_infix /prism/src/prism.c:21492:34
    #13 0xaaaabe7ff204 in parse_expression /prism/src/prism.c:21589:16
    #14 0xaaaabe7fb804 in parse_statements /prism/src/prism.c:13163:27
    #15 0xaaaabe816c24 in parse_expression_prefix /prism/src/prism.c:20071:28
    #16 0xaaaabe7fed90 in parse_expression /prism/src/prism.c:21537:23
    #17 0xaaaabe850954 in parse_value_expression /prism/src/prism.c:12430:23
    #18 0xaaaabe850954 in parse_arguments /prism/src/prism.c:13562:32
    #19 0xaaaabe82ab04 in parse_expression_infix /prism/src/prism.c:21426:17
    #20 0xaaaabe7ff204 in parse_expression /prism/src/prism.c:21589:16
    #21 0xaaaabe850954 in parse_value_expression /prism/src/prism.c:12430:23
    #22 0xaaaabe850954 in parse_arguments /prism/src/prism.c:13562:32
    #23 0xaaaabe8490b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #24 0xaaaabe82d240 in parse_expression_infix /prism/src/prism.c:21244:13
    #25 0xaaaabe7ff204 in parse_expression /prism/src/prism.c:21589:16
    #26 0xaaaabe7fb804 in parse_statements /prism/src/prism.c:13163:27
    #27 0xaaaabe7be274 in parse_program /prism/src/prism.c:21810:40
    #28 0xaaaabe7be274 in pm_parse /prism/src/prism.c:22242:12
    #29 0xaaaabe8d2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #30 0xaaaabe904320 in harness /prism/fuzz/parse.c:9:5
    #31 0xaaaabe9044c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #32 0xaaaabe796034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #33 0xaaaabe795ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #34 0xaaaabe795988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"f=>{/000000000000\\M-\\'0"
*/
static const uint8_t input[] = {0x66, 0x3d, 0x3e, 0x7b, 0x2f, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x5c, 0x4d, 0x2d, 0x5c, 0x27, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
