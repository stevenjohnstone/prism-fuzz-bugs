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
==51648==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaaccb2daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaacccc1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaaccb9e5b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaaccb9e5b8 in parser_lex /prism/src/prism.c:11654:25
    #4 0xaaaaccbd57cc in parse_expression_prefix /prism/src/prism.c:18070:13
    #5 0xaaaaccbced90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaaccbcb804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaaccc7e688 in parse_conditional /prism/src/prism.c:15119:22
    #8 0xaaaaccbdcd60 in parse_expression_prefix /prism/src/prism.c
    #9 0xaaaaccbced90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaaccc604d4 in parse_value_expression /prism/src/prism.c:12430:23
    #11 0xaaaaccc604d4 in parse_assocs /prism/src/prism.c:13363:34
    #12 0xaaaaccbe11b0 in parse_expression_prefix /prism/src/prism.c:17728:21
    #13 0xaaaaccbced90 in parse_expression /prism/src/prism.c:21537:23
    #14 0xaaaaccbcb804 in parse_statements /prism/src/prism.c:13163:27
    #15 0xaaaaccc4cb1c in parse_rescues /prism/src/prism.c:14490:33
    #16 0xaaaaccc79208 in parse_rescues_implicit_begin /prism/src/prism.c:14518:5
    #17 0xaaaaccbead88 in parse_expression_prefix /prism/src/prism.c:18901:34
    #18 0xaaaaccbced90 in parse_expression /prism/src/prism.c:21537:23
    #19 0xaaaaccc00db8 in parse_value_expression /prism/src/prism.c:12430:23
    #20 0xaaaaccc00db8 in parse_starred_expression /prism/src/prism.c:12521:12
    #21 0xaaaaccc00db8 in parse_assignment_values /prism/src/prism.c:20228:24
    #22 0xaaaaccbfcc24 in parse_expression_infix /prism/src/prism.c:20599:40
    #23 0xaaaaccbcf204 in parse_expression /prism/src/prism.c:21589:16
    #24 0xaaaaccbcb804 in parse_statements /prism/src/prism.c:13163:27
    #25 0xaaaaccb8e274 in parse_program /prism/src/prism.c:21810:40
    #26 0xaaaaccb8e274 in pm_parse /prism/src/prism.c:22242:12
    #27 0xaaaaccca2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #28 0xaaaacccd4320 in harness /prism/fuzz/parse.c:9:5
    #29 0xaaaacccd44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #30 0xaaaaccb66034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #31 0xaaaaccb65ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #32 0xaaaaccb65988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #33 0xffff83ed73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #34 0xffff83ed74d4 in __libc_start_main csu/../csu/libc-start.c:392:3

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":.`\#@w\r\n"
*/
static const uint8_t input[] = {0x3a, 0x2e, 0x60, 0x23, 0x40, 0x77, 0x0d, 0x0a};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
