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
==23120==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab425daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab42d21bc in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaab42d21bc in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaab42d21bc in parser_lex /prism/src/prism.c:11998:25
    #4 0xaaaab42fbb2c in parse_statements /prism/src/prism.c:13204:13
    #5 0xaaaab43569c0 in parse_block /prism/src/prism.c:14736:26
    #6 0xaaaab4348970 in parse_arguments_list /prism/src/prism.c:14822:21
    #7 0xaaaab430fb44 in parse_expression_prefix /prism/src/prism.c:17921:21
    #8 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #9 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #10 0xaaaab4316b14 in parse_expression_prefix /prism/src/prism.c:20060:28
    #11 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #12 0xaaaab43904d4 in parse_value_expression /prism/src/prism.c:12430:23
    #13 0xaaaab43904d4 in parse_assocs /prism/src/prism.c:13363:34
    #14 0xaaaab43111b0 in parse_expression_prefix /prism/src/prism.c:17728:21
    #15 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #16 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #17 0xaaaab4316b14 in parse_expression_prefix /prism/src/prism.c:20060:28
    #18 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #19 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #20 0xaaaab43569c0 in parse_block /prism/src/prism.c:14736:26
    #21 0xaaaab4348970 in parse_arguments_list /prism/src/prism.c:14822:21
    #22 0xaaaab430fb44 in parse_expression_prefix /prism/src/prism.c:17921:21
    #23 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #24 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #25 0xaaaab4316b14 in parse_expression_prefix /prism/src/prism.c:20060:28
    #26 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #27 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #28 0xaaaab42be274 in parse_program /prism/src/prism.c:21810:40
    #29 0xaaaab42be274 in pm_parse /prism/src/prism.c:22242:12
    #30 0xaaaab43d2800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #31 0xaaaab4404320 in harness /prism/fuzz/parse.c:9:5
    #32 0xaaaab44044c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #33 0xaaaab4296034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaab425daa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaab42d21bc in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaab42d21bc in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaab42d21bc in parser_lex /prism/src/prism.c:11998:25
    #4 0xaaaab4361058 in parse_pattern_primitive /prism/src/prism.c:16637:25
    #5 0xaaaab4362ae0 in parse_pattern_primitives /prism/src/prism.c:16850:28
    #6 0xaaaab4359114 in parse_pattern /prism/src/prism.c
    #7 0xaaaab435dc2c in parse_pattern_hash /prism/src/prism.c:16435:29
    #8 0xaaaab4358f0c in parse_pattern /prism/src/prism.c:16938:20
    #9 0xaaaab4328684 in parse_expression_infix /prism/src/prism.c:21475:34
    #10 0xaaaab42ff204 in parse_expression /prism/src/prism.c:21589:16
    #11 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #12 0xaaaab43569c0 in parse_block /prism/src/prism.c:14736:26
    #13 0xaaaab4348970 in parse_arguments_list /prism/src/prism.c:14822:21
    #14 0xaaaab430fb44 in parse_expression_prefix /prism/src/prism.c:17921:21
    #15 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #16 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #17 0xaaaab4316b14 in parse_expression_prefix /prism/src/prism.c:20060:28
    #18 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #19 0xaaaab43904d4 in parse_value_expression /prism/src/prism.c:12430:23
    #20 0xaaaab43904d4 in parse_assocs /prism/src/prism.c:13363:34
    #21 0xaaaab43111b0 in parse_expression_prefix /prism/src/prism.c:17728:21
    #22 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #23 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #24 0xaaaab4316b14 in parse_expression_prefix /prism/src/prism.c:20060:28
    #25 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #26 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #27 0xaaaab43569c0 in parse_block /prism/src/prism.c:14736:26
    #28 0xaaaab4348970 in parse_arguments_list /prism/src/prism.c:14822:21
    #29 0xaaaab430fb44 in parse_expression_prefix /prism/src/prism.c:17921:21
    #30 0xaaaab42fed90 in parse_expression /prism/src/prism.c:21537:23
    #31 0xaaaab42fb804 in parse_statements /prism/src/prism.c:13163:27
    #32 0xaaaab4316b14 in parse_expression_prefix /prism/src/prism.c:20060:28

SUMMARY: AddressSanitizer: 32 byte(s) leaked in 2 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
"-in   {<<~0\n\n\\ "
*/
static const uint8_t input[] = {0x2d, 0x69, 0x6e, 0x20, 0x20, 0x20, 0x7b, 0x3c,
                                0x3c, 0x7e, 0x30, 0x0a, 0x0a, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
