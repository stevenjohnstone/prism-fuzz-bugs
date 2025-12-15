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
==2459==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaadfd3daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaadfed1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaadfdae5b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaadfdae5b8 in parser_lex /prism/src/prism.c:11654:25
    #4 0xaaaadfe0d20c in parse_expression_infix /prism/src/prism.c:21234:21
    #5 0xaaaadfddf204 in parse_expression /prism/src/prism.c:21589:16
    #6 0xaaaadfe30954 in parse_value_expression /prism/src/prism.c:12430:23
    #7 0xaaaadfe30954 in parse_arguments /prism/src/prism.c:13562:32
    #8 0xaaaadfe290b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #9 0xaaaadfdeef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #10 0xaaaadfdded90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaadfddb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaadfd9e274 in parse_program /prism/src/prism.c:21810:40
    #13 0xaaaadfd9e274 in pm_parse /prism/src/prism.c:22242:12
    #14 0xaaaadfeb2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #15 0xaaaadfee4320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaadfee44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaadfd76034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaadfd75ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaadfd75988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffff870173fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffff870174d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaadfc9f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":.`\r\n"
*/
static const uint8_t input[] = {0x3a, 0x2e, 0x60, 0x0d, 0x0a};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
