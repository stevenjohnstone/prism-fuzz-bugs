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
==5288==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaac81ede98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaac838243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaac838243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaac838243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaac825e414 in pm_token_buffer_escape /prism/src/prism.c:9619:5
    #5 0xaaaac825e414 in parser_lex /prism/src/prism.c:11685:25
    #6 0xaaaac828bb2c in parse_statements /prism/src/prism.c:13204:13
    #7 0xaaaac824e274 in parse_program /prism/src/prism.c:21810:40
    #8 0xaaaac824e274 in pm_parse /prism/src/prism.c:22242:12
    #9 0xaaaac8362800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #10 0xaaaac8394320 in harness /prism/fuzz/parse.c:9:5
    #11 0xaaaac83944c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #12 0xaaaac8226034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #13 0xaaaac8225ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #14 0xaaaac8225988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #15 0xffffbba573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #16 0xffffbba574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #17 0xaaaac814f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaac81edaa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaac8381518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaac825e3b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaac825e3b8 in parser_lex /prism/src/prism.c:11685:25
    #4 0xaaaac82bd20c in parse_expression_infix /prism/src/prism.c:21234:21
    #5 0xaaaac828f204 in parse_expression /prism/src/prism.c:21589:16
    #6 0xaaaac828b804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaac824e274 in parse_program /prism/src/prism.c:21810:40
    #8 0xaaaac824e274 in pm_parse /prism/src/prism.c:22242:12
    #9 0xaaaac8362800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #10 0xaaaac8394320 in harness /prism/fuzz/parse.c:9:5
    #11 0xaaaac83944c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #12 0xaaaac8226034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #13 0xaaaac8225ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #14 0xaaaac8225988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #15 0xffffbba573fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #16 0xffffbba574d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #17 0xaaaac814f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 80 byte(s) leaked in 2 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":.`000000000000000000000000000000000\\)"
*/
static const uint8_t input[] = {0x3a, 0x2e, 0x60, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x5c, 0x29};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
