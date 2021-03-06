/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2020 Justine Alexandra Roberts Tunney                              │
│                                                                              │
│ Permission to use, copy, modify, and/or distribute this software for         │
│ any purpose with or without fee is hereby granted, provided that the         │
│ above copyright notice and this permission notice appear in all copies.      │
│                                                                              │
│ THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL                │
│ WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                │
│ WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE             │
│ AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL         │
│ DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR        │
│ PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER               │
│ TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR             │
│ PERFORMANCE OF THIS SOFTWARE.                                                │
╚─────────────────────────────────────────────────────────────────────────────*/
#include "libc/bits/bits.h"
#include "libc/fmt/conv.h"
#include "libc/limits.h"
#include "libc/testlib/testlib.h"

TEST(strtoumax, testZero) {
  EXPECT_EQ(UINTMAX_MIN, strtoumax("0", NULL, 0));
}
TEST(strtoumax, testDecimal) {
  EXPECT_EQ(123, strtoumax("123", NULL, 0));
}
TEST(strtoumax, testHex) {
  EXPECT_EQ(255, strtoumax("0xff", NULL, 0));
  EXPECT_EQ(255, strtoumax("0xff", NULL, 16));
}
TEST(strtoumax, testOctal) {
  EXPECT_EQ(123, strtoumax("0173", NULL, 0));
  EXPECT_EQ(123, strtoumax("0173", NULL, 8));
}
TEST(strtoumax, testBinary) {
  EXPECT_EQ(42, strtoumax("0b101010", NULL, 0));
  EXPECT_EQ(42, strtoumax("0b101010", NULL, 2));
}

TEST(strtoumax, testMaximum) {
  EXPECT_EQ(UINTMAX_MAX,
            strtoumax("340282366920938463463374607431768211455", NULL, 0));
  EXPECT_EQ(UINTMAX_MAX,
            strtoumax("0xffffffffffffffffffffffffffffffff", NULL, 0));
}

TEST(strtoumax, testTwosBane) {
  EXPECT_EQ(((uintmax_t)0x8000000000000000) << 64 | 0x0000000000000000,
            strtoumax("0x80000000000000000000000000000000", NULL, 0));
}
