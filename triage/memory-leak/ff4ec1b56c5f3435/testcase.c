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
==62392==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 3 byte(s) in 1 object(s) allocated from:
    #0 0xaaaac914daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaac92e1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaac91cc510 in lex_question_mark /prism/src/prism.c:9224:9
    #3 0xaaaac91cc510 in parser_lex /prism/src/prism.c:10502:21
    #4 0xaaaac9205704 in accept2 /prism/src/prism.c:12363:9
    #5 0xaaaac9205704 in parse_expression_prefix /prism/src/prism.c:18334:13
    #6 0xaaaac91eed90 in parse_expression /prism/src/prism.c:21537:23
    #7 0xaaaac91eb804 in parse_statements /prism/src/prism.c:13163:27
    #8 0xaaaac91ae274 in parse_program /prism/src/prism.c:21810:40
    #9 0xaaaac91ae274 in pm_parse /prism/src/prism.c:22242:12
    #10 0xaaaac92c2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #11 0xaaaac92f4320 in harness /prism/fuzz/parse.c:9:5
    #12 0xaaaac92f44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #13 0xaaaac9186034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #14 0xaaaac9185ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #15 0xaaaac9185988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #16 0xffff8e2173fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #17 0xffff8e2174d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #18 0xaaaac90af22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 3 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"case in class end\n?\\ "
*/
static const uint8_t input[] = {0x63, 0x61, 0x73, 0x65, 0x20, 0x69, 0x6e,
                                0x20, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x20,
                                0x65, 0x6e, 0x64, 0x0a, 0x3f, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
