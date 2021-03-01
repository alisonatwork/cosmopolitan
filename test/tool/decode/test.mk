#-*-mode:makefile-gmake;indent-tabs-mode:t;tab-width:8;coding:utf-8-*-┐
#───vi: set et ft=make ts=8 tw=8 fenc=utf-8 :vi───────────────────────┘

PKGS += TEST_TOOL_DECODE

TEST_TOOL_DECODE_SRCS := $(wildcard test/tool/decode/*.c)
TEST_TOOL_DECODE_SRCS_TEST = $(filter %_test.c,$(TEST_TOOL_DECODE_SRCS))

TEST_TOOL_DECODE_OBJS =				\
	$(TEST_TOOL_DECODE_SRCS:%.c=o/$(MODE)/%.o)

TEST_TOOL_DECODE_COMS =				\
	$(TEST_TOOL_DECODE_SRCS:%.c=o/$(MODE)/%.com)

TEST_TOOL_DECODE_BINS =				\
	$(TEST_TOOL_DECODE_COMS)			\
	$(TEST_TOOL_DECODE_COMS:%=%.dbg)

TEST_TOOL_DECODE_TESTS =				\
	$(TEST_TOOL_DECODE_SRCS_TEST:%.c=o/$(MODE)/%.com.ok)

TEST_TOOL_DECODE_CHECKS =				\
	$(TEST_TOOL_DECODE_SRCS_TEST:%.c=o/$(MODE)/%.com.runs)

TEST_TOOL_DECODE_DIRECTDEPS =				\
	LIBC_ELF					\
	LIBC_FMT					\
	LIBC_RUNTIME					\
	LIBC_STDIO					\
	LIBC_SYSV					\
	LIBC_TESTLIB

TEST_TOOL_DECODE_DEPS :=				\
	$(call uniq,$(foreach x,$(TEST_TOOL_DECODE_DIRECTDEPS),$($(x))))

o/$(MODE)/test/tool/decode/vizlib.pkg:			\
		$(TEST_TOOL_DECODE_OBJS)		\
		$(foreach x,$(TEST_TOOL_DECODE_DIRECTDEPS),$($(x)_A).pkg)

o/$(MODE)/test/tool/decode/%.com.dbg:			\
		$(TEST_TOOL_DECODE_DEPS)		\
		o/$(MODE)/test/tool/decode/%.o		\
		$(LIBC_TESTMAIN)			\
		$(CRT)					\
		$(APE)
	@$(APELINK)

.PHONY:		o/$(MODE)/test/tool/decode
o/$(MODE)/test/tool/decode:				\
		$(TEST_TOOL_DECODE_BINS)		\
		$(TEST_TOOL_DECODE_CHECKS)
