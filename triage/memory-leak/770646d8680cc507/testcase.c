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
==11022==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 3 byte(s) in 1 object(s) allocated from:
    #0 0xaaaace6adaa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaace841518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaace72c510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaace72c510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaace7563dc in parse_expression_prefix /prism/src/prism.c:19525:25
    #5 0xaaaace74ed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaace74b804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaace76abf8 in parse_expression_prefix /prism/src/prism.c:18895:34
    #8 0xaaaace74ed90 in parse_expression /prism/src/prism.c:21537:23
    #9 0xaaaace74b804 in parse_statements /prism/src/prism.c:13163:27
    #10 0xaaaace70e274 in parse_program /prism/src/prism.c:21810:40
    #11 0xaaaace70e274 in pm_parse /prism/src/prism.c:22242:12
    #12 0xaaaace822800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #13 0xaaaace854320 in harness /prism/fuzz/parse.c:9:5
    #14 0xaaaace8544c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #15 0xaaaace6e6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #16 0xaaaace6e5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #17 0xaaaace6e5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #18 0xffffa1c773fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #19 0xffffa1c774d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #20 0xaaaace60f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 3 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"def !\n%I \#{end ?\\b"
*/
static const uint8_t input[] = {0x64, 0x65, 0x66, 0x20, 0x21, 0x0a,
                                0x25, 0x49, 0x20, 0x23, 0x7b, 0x65,
                                0x6e, 0x64, 0x20, 0x3f, 0x5c, 0x62};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
