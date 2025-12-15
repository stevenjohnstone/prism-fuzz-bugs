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
==49633==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab65cde98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab67627a0 in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaab67627a0 in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaab67627a0 in pm_buffer_append_byte /prism/src/util/pm_buffer.c:137:5
    #4 0xaaaab663d484 in pm_token_buffer_push_byte /prism/src/prism.c:9496:5
    #5 0xaaaab663d484 in parser_lex /prism/src/prism.c:11480:52
    #6 0xaaaab66d1058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #7 0xaaaab66d3318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #8 0xaaaab66c94a0 in parse_pattern /prism/src/prism.c:17023:24
    #9 0xaaaab66d0840 in parse_pattern_primitive /prism/src/prism.c:16566:32
    #10 0xaaaab66d3318 in parse_pattern_primitives /prism/src/prism.c:16853:40
    #11 0xaaaab66c9114 in parse_pattern /prism/src/prism.c
    #12 0xaaaab6698684 in parse_expression_infix /prism/src/prism.c:21475:34
    #13 0xaaaab666f204 in parse_expression /prism/src/prism.c:21589:16
    #14 0xaaaab666b804 in parse_statements /prism/src/prism.c:13163:27
    #15 0xaaaab662e274 in parse_program /prism/src/prism.c:21810:40
    #16 0xaaaab662e274 in pm_parse /prism/src/prism.c:22242:12
    #17 0xaaaab6742800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #18 0xaaaab6774320 in harness /prism/fuzz/parse.c:9:5
    #19 0xaaaab67744c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #20 0xaaaab6606034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #21 0xaaaab6605ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #22 0xaaaab6605988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #23 0xffffb45e73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #24 0xffffb45e74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #25 0xaaaab652f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"1in {/00000000000000000000000000000000\\0"
*/
static const uint8_t input[] = {0x31, 0x69, 0x6e, 0x20, 0x7b, 0x2f, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5c, 0x30};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
