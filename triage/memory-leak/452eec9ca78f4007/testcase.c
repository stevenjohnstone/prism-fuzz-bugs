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
==40419==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 64 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad52cde98 in realloc (/prism/build/fuzz+0x17de98) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad546243c in pm_buffer_append_length /prism/src/util/pm_buffer.c:63:25
    #2 0xaaaad546243c in pm_buffer_append /prism/src/util/pm_buffer.c:77:9
    #3 0xaaaad546243c in pm_buffer_append_bytes /prism/src/util/pm_buffer.c:128:5
    #4 0xaaaad543f524 in escape_write_escape_encoded /prism/src/prism.c:8725:9
    #5 0xaaaad533e784 in parser_lex /prism/src/prism.c:11731:37
    #6 0xaaaad539d20c in parse_expression_infix /prism/src/prism.c:21234:21
    #7 0xaaaad536f204 in parse_expression /prism/src/prism.c:21589:16
    #8 0xaaaad53c0954 in parse_value_expression /prism/src/prism.c:12430:23
    #9 0xaaaad53c0954 in parse_arguments /prism/src/prism.c:13562:32
    #10 0xaaaad53b90b8 in parse_arguments_list /prism/src/prism.c:14802:9
    #11 0xaaaad537ef38 in parse_expression_prefix /prism/src/prism.c:17895:21
    #12 0xaaaad536ed90 in parse_expression /prism/src/prism.c:21537:23
    #13 0xaaaad536b804 in parse_statements /prism/src/prism.c:13163:27
    #14 0xaaaad532e274 in parse_program /prism/src/prism.c:21810:40
    #15 0xaaaad532e274 in pm_parse /prism/src/prism.c:22242:12
    #16 0xaaaad5442800 in pm_serialize_parse /prism/src/prism.c:22410:23
    #17 0xaaaad5474320 in harness /prism/fuzz/parse.c:9:5
    #18 0xaaaad54744c8 in LLVMFuzzerTestOneInput /prism/fuzz/fuzz.c:82:5
    #19 0xaaaad5306034 in ExecuteFilesOnyByOne /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:260:7
    #20 0xaaaad5305ec8 in LLVMFuzzerRunDriver /AFLplusplus/utils/aflpp_driver/aflpp_driver.c
    #21 0xaaaad5305988 in main /AFLplusplus/utils/aflpp_driver/aflpp_driver.c:316:10
    #22 0xffff91ec73fc in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #23 0xffff91ec74d4 in __libc_start_main csu/../csu/libc-start.c:392:3
    #24 0xaaaad522f22c in _start (/prism/build/fuzz+0xdf22c) (BuildId: 27a80e0520a7c276)

SUMMARY: AddressSanitizer: 64 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":.`0000000000000000000000000000000\\\u00AB"
*/
static const uint8_t input[] = {0x3a, 0x2e, 0x60, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
                                0x30, 0x30, 0x5c, 0xc2, 0xab};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
