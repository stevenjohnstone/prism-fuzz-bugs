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
==10718==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad539de98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad553243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad553243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad553243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaad540d36c in pm_regexp_token_buffer_escape /prism/src/prism.c:9636:5
    #5 0xaaaad540d36c in parser_lex /prism/src/prism.c:11422:25
    #6 0xaaaad54a1058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaad54a2ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #8 0xaaaad5499114 in parse_pattern /prism/src/prism.c
    #9 0xaaaad5468684 in parse_expression_infix /prism/src/prism.c:21475:34
    #10 0xaaaad543f204 in parse_expression /prism/src/prism.c:21589:16
    #11 0xaaaad543b804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaad53fe274 in parse_program /prism/src/prism.c:21810:40
    #13 0xaaaad53fe274 in pm_parse /prism/src/prism.c:22242:12
    #14 0xaaaad5512800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #15 0xaaaad5544320 in harness /prism/fuzz/parse.c:9:5
    #16 0xaaaad55444c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #17 0xaaaad53d6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #18 0xaaaad53d5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #19 0xaaaad53d5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #20 0xffff9dfa73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #21 0xffff9dfa74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #22 0xaaaad52ff22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"''in{/000000000000000000000000000000000\\0"
*/
static const uint8_t input[] = {
    0x27, 0x27, 0x69, 0x6e, 0x7b, 0x2f, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
