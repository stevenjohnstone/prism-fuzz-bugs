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
==6779==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab5b6daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab5d01518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaab5bde3b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaab5bde3b8 in parser_lex /prism/src/prism.c:11685:25
    #4 0xaaaab5c14f4c in parse_expression_prefix /prism/src/prism.c:17773:13
    #5 0xaaaab5c0ed90 in parse_expression /prism/src/prism.c:21537:23
    #6 0xaaaab5c0b804 in parse_statements /prism/src/prism.c:13163:27
    #7 0xaaaab5c21f78 in parse_expression_prefix /prism/src/prism.c:19203:30
    #8 0xaaaab5c0ed90 in parse_expression /prism/src/prism.c:21537:23
    #9 0xaaaab5c0b804 in parse_statements /prism/src/prism.c:13163:27
    #10 0xaaaab5bce274 in parse_program /prism/src/prism.c:21810:40
    #11 0xaaaab5bce274 in pm_parse /prism/src/prism.c:22242:12
    #12 0xaaaab5ce2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #13 0xaaaab5d14320 in harness /prism/fuzz/parse.c:9:5
    #14 0xaaaab5d144c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #15 0xaaaab5ba6034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #16 0xaaaab5ba5ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #17 0xaaaab5ba5988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #18 0xffff998873fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #19 0xffff998874d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #20 0xaaaab5acf22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":\x1E:`\#@@t\\="
*/
static const uint8_t input[] = {0x3a, 0x1e, 0x3a, 0x60, 0x23,
                                0x40, 0x40, 0x74, 0x5c, 0x3d};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
