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
==18793==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaade84daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaade9e1518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaade8be3b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaade8be3b8 in parser_lex /prism/src/prism.c:11685:25
    #4 0xaaaade91d908 in parse_expression_infix /prism/src/prism.c:21378:21
    #5 0xaaaade8ef204 in parse_expression /prism/src/prism.c:21589:16
    #6 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #7 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #8 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #9 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #10 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #11 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #12 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #13 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #14 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #15 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #16 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #17 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #18 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #19 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #20 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #21 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #22 0xaaaade8fcf54 in parse_expression_prefix /prism/src/prism.c:19977:35
    #23 0xaaaade8eed90 in parse_expression /prism/src/prism.c:21537:23
    #24 0xaaaade919b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #25 0xaaaade8ef204 in parse_expression /prism/src/prism.c:21589:16
    #26 0xaaaade8eb804 in parse_statements /prism/src/prism.c:13163:27
    #27 0xaaaade8ae274 in parse_program /prism/src/prism.c:21810:40
    #28 0xaaaade8ae274 in pm_parse /prism/src/prism.c:22242:12
    #29 0xaaaade9c2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #30 0xaaaade9f4320 in harness /prism/fuzz/parse.c:9:5
    #31 0xaaaade9f44c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":\xFA::`\\ "
*/
static const uint8_t input[] = {0x3a, 0xfa, 0x3a, 0x3a, 0x60, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
