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
==39378==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 128 byte(s) in 1 object(s) allocated from:
    #0 0xaaaabb38de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaabb5227a0 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaabb5227a0 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaabb5227a0 in pm_buffer_append_byte /prism/src/util/pm_buffer.c:137:5
    #4 0xaaaabb3fe9e8 in pm_token_buffer_push_byte /prism/src/prism.c:9496:5
    #5 0xaaaabb3fe9e8 in parser_lex /prism/src/prism.c:11699:37
    #6 0xaaaabb45d20c in parse_expression_infix /prism/src/prism.c:21234:21
    #7 0xaaaabb42f204 in parse_expression /prism/src/prism.c:21589:16
    #8 0xaaaabb480954 in parse_value_expression /prism/src/prism.c:12430:23
    #9 0xaaaabb480954 in parse_arguments /prism/src/prism.c:13562:32
    #10 0xaaaabb4790b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #11 0xaaaabb435778 in parse_expression_prefix /prism/src/prism.c:17795:17
    #12 0xaaaabb42ed90 in parse_expression /prism/src/prism.c:21537:23
    #13 0xaaaabb42b804 in parse_statements /prism/src/prism.c:13163:27
    #14 0xaaaabb4869c0 in parse_block /prism/src/prism.c:14736:26
    #15 0xaaaabb478970 in parse_arguments_list /prism/src/prism.c:14822:21
    #16 0xaaaabb43ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #17 0xaaaabb42ed90 in parse_expression /prism/src/prism.c:21537:23
    #18 0xaaaabb480954 in parse_value_expression /prism/src/prism.c:12430:23
    #19 0xaaaabb480954 in parse_arguments /prism/src/prism.c:13562:32
    #20 0xaaaabb4790b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #21 0xaaaabb43ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #22 0xaaaabb42ed90 in parse_expression /prism/src/prism.c:21537:23
    #23 0xaaaabb42b804 in parse_statements /prism/src/prism.c:13163:27
    #24 0xaaaabb3ee274 in parse_program /prism/src/prism.c:21810:40
    #25 0xaaaabb3ee274 in pm_parse /prism/src/prism.c:22242:12
    #26 0xaaaabb502800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #27 0xaaaabb534320 in harness /prism/fuzz/parse.c:9:5
    #28 0xaaaabb5344c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #29 0xaaaabb3c6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #30 0xaaaabb3c5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #31 0xaaaabb3c5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #32 0xffff99ea73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #33 0xffff99ea74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #34 0xaaaabb2ef22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 128 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":.`0000000000000000000000000000000000000000000000000000000000000000\\\r"
*/
static const uint8_t input[] = {
    0x3a, 0x2e, 0x60, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x0d};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
