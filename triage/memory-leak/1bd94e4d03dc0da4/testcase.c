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
==34362==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaacf83daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaacf9d1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaacf8ae5b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaacf8ae5b8 in parser_lex /prism/src/prism.c:11654:25
    #4 0xaaaacf98aca8 in parse_method_definition_name /prism/src/prism.c
    #5 0xaaaacf8fb774 in parse_expression_prefix /prism/src/prism.c:18766:28
    #6 0xaaaacf8ded90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaacf8db804 in parse_statements /prism/src/prism.c:13163:27
    #8 0xaaaacf89e274 in parse_program /prism/src/prism.c:21810:40
    #9 0xaaaacf89e274 in pm_parse /prism/src/prism.c:22242:12
    #10 0xaaaacf9b2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #11 0xaaaacf9e4320 in harness /prism/fuzz/parse.c:9:5
    #12 0xaaaacf9e44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #13 0xaaaacf876034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #14 0xaaaacf875ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #15 0xaaaacf875988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #16 0xffff849c73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #17 0xffff849c74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #18 0xaaaacf79f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"def(F<_`\r\n"
*/
static const uint8_t input[] = {0x64, 0x65, 0x66, 0x28, 0x46,
                                0x3c, 0x5f, 0x60, 0x0d, 0x0a};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
