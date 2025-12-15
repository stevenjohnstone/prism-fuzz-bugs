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
==2632==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0xaaaaad15de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaaad2f27a0 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaaad2f27a0 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaaad2f27a0 in pm_buffer_append_byte /prism/src/util/pm_buffer.c:137:5
    #4 0xaaaaad1ce784 in parser_lex /prism/src/prism.c:11731:37
    #5 0xaaaaad22d20c in parse_expression_infix /prism/src/prism.c:21234:21
    #6 0xaaaaad1ff204 in parse_expression /prism/src/prism.c:21589:16
    #7 0xaaaaad250954 in parse_value_expression /prism/src/prism.c:12430:23
    #8 0xaaaaad250954 in parse_arguments /prism/src/prism.c:13562:32
    #9 0xaaaaad2490b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #10 0xaaaaad20ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #11 0xaaaaad1fed90 in parse_expression /prism/src/prism.c:21537:23
    #12 0xaaaaad1fb804 in parse_statements /prism/src/prism.c:13163:27
    #13 0xaaaaad1be274 in parse_program /prism/src/prism.c:21810:40
    #14 0xaaaaad1be274 in pm_parse /prism/src/prism.c:22242:12
    #15 0xaaaaad2d2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #16 0xaaaaad304320 in harness /prism/fuzz/parse.c:9:5
    #17 0xaaaaad3044c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #18 0xaaaaad196034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #19 0xaaaaad195ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #20 0xaaaaad195988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #21 0xffffbcd573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #22 0xffffbcd574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #23 0xaaaaad0bf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":.`0000000000000000\\ "
*/
static const uint8_t input[] = {0x3a, 0x2e, 0x60, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
