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
==24512==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 16 byte(s) in 1 object(s) allocated from:
    #0 0xaaaad2bedaa0 in malloc (/prism/build/fuzz+0x17daa0) (BuildId: 27a80e0520a7c276)
    #1 0xaaaad2d81518 in pm_buffer_init_capacity /prism/src/util/pm_buffer.c:19:30
    #2 0xaaaad2c5e3b8 in pm_token_buffer_escape /prism/src/prism.c:9611:9
    #3 0xaaaad2c5e3b8 in parser_lex /prism/src/prism.c:11685:25
    #4 0xaaaad2cbd20c in parse_expression_infix /prism/src/prism.c:21234:21
    #5 0xaaaad2c8f204 in parse_expression /prism/src/prism.c:21589:16
    #6 0xaaaad2cb9b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #7 0xaaaad2c8f204 in parse_expression /prism/src/prism.c:21589:16
    #8 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #9 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #10 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #11 0xaaaad2cb9b9c in parse_expression_infix /prism/src/prism.c:21173:35
    #12 0xaaaad2c8f204 in parse_expression /prism/src/prism.c:21589:16
    #13 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #14 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #15 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #16 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #17 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #18 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #19 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #20 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #21 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #22 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #23 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #24 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #25 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #26 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #27 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #28 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #29 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #30 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #31 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #32 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #33 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #34 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #35 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #36 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #37 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #38 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31
    #39 0xaaaad2c8ed90 in parse_expression /prism/src/prism.c:21537:23
    #40 0xaaaad2c93978 in parse_value_expression /prism/src/prism.c:12430:23
    #41 0xaaaad2c93978 in parse_expression_prefix /prism/src/prism.c:17445:31

SUMMARY: AddressSanitizer: 16 byte(s) leaked in 1 allocation(s).

*/

// Cause ASAN to call abort on an error to make
// debugging inside gdb easier
const char *__asan_default_options() {
  return "abort_on_error=1:handle_abort=1";
}

/*
":.`\\ "
*/
static const uint8_t input[] = {0x3a, 0x2e, 0x60, 0x5c, 0x20};

int main(int argc, const char **argv) {
  (void)argc;
  (void)argv;
  harness(input, sizeof(input));
  return 0;
}
