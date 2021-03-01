/*-*- mode:c;indent-tabs-mode:nil;c-basic-offset:2;tab-width:8;coding:utf-8 -*-│
│vi: set net ft=c ts=2 sts=2 sw=2 fenc=utf-8                                :vi│
╞══════════════════════════════════════════════════════════════════════════════╡
│ Copyright 2021 Alison Winters                                                │
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
#include "libc/calls/calls.h"
#include "libc/calls/struct/stat.h"
#include "libc/elf/elf.h"
#include "libc/macho.internal.h"
#include "libc/nt/struct/imagedosheader.internal.h"
#include "libc/nt/struct/imagentheaders.internal.h"
#include "libc/stdio/stdio.h"
#include "libc/sysv/consts/map.h"
#include "libc/sysv/consts/o.h"
#include "libc/sysv/consts/prot.h"

/**
 * @fileoverview Tool for inspecting APE binaries.
 */

#define APE_HEADER "MZqFpD='\n"
#define APE_HEADER_SIZE 9

// test
// any random file start with MZ - short
// MZ that isn't an APE
// MZ that is an ape
// any random file start with ELF

int main(int argc, char *argv[]) {
  int64_t fd;
  struct stat st[1];
  const char *path;
  void *map;
  size_t mapsize;
  bool is_ape;
  struct NtImageDosHeader *mz;
  struct NtImageNtHeaders *pe;
  Elf64_Ehdr *elf;
  struct MachoHeader *macho;

  if (argc != 2) fprintf(stderr, "usage: %s FILE\n", argv[0]), exit(1);
  if ((fd = open((path = argv[1]), O_RDONLY)) == -1 || fstat(fd, st) == -1 ||
      (map = mmap(NULL, (mapsize = st->st_size), PROT_READ, MAP_SHARED, fd, 0)) ==
          MAP_FAILED) {
    fprintf(stderr, "error: %'s %m\n", path);
    exit(1);
  }
  if (mapsize < APE_HEADER_SIZE) {
    fprintf(stderr, "error: %'s file too small %d\n", path, mapsize);
    exit(1);
  }
  if (memcmp(map, APE_HEADER, APE_HEADER_SIZE) == 0) {
    printf("found ape header\n");
    is_ape = true;
  }
  mz = (struct NtImageDosHeader *) map;
  elf = (Elf64_Ehdr *) map;
  macho = (struct MachoHeader *) map;
  if (mz->e_magic == kNtImageDosSignature) {
    if (!is_ape) {
      printf("found dos header\n");
    }
    if (mapsize < sizeof(*mz)) {
      fprintf(stderr, "error: %'s dos file too small\n", path);
      exit(1);
    }
    if (mz->e_oemid != ('J' | 'T' << 8)) { /* ape oem */
      fprintf(stderr, "error: %'s unexpected dos oemid 0x%x\n", path, mz->e_oemid);
      exit(1);
    }
    if (mz->e_lfanew == 0) {
      printf("no win main\n"); /* but still probably an elf and macho macho main */
    } else {
      pe = (struct NtImageNtHeaders *) ((intptr_t) mz + mz->e_lfanew);
#if !(TRUSTWORTHY + PE_TRUSTWORTHY + 0)
      if ((intptr_t)pe < (intptr_t)map ||
          (intptr_t)pe + sizeof(struct NtImageFileHeader) > (intptr_t)map + mapsize) {
        abort();
      }   
#endif
      if (pe->Signature != ('P' | 'E' << 8)) { /* pe header, 4 bytes, "PE" + NUL + NUL */
        fprintf(stderr, "error: %'s corrupt pe signature @ 0x%x 0x%x\n", path, mz->e_lfanew, mz->e_oemid);
        exit(1);
      }
      printf("win main @ 0x%x\n", pe->OptionalHeader.AddressOfEntryPoint);
    }
  } else if (IsElf64Binary(elf, mapsize)) {
    printf("found elf header\n");
    if (mapsize < sizeof(*elf)) {
      fprintf(stderr, "error: %'s elf file too small\n", path);
      exit(1);
    }
    if (elf->e_ident[EI_CLASS] != ELFCLASS64) { /* 64 bit */
      fprintf(stderr, "error: %'s unexpected elf class 0x%d\n", path, elf->e_ident[EI_CLASS]);
      exit(1);
    }
    if (elf->e_ident[EI_DATA] != ELFDATA2LSB) { /* little endian */
      fprintf(stderr, "error: %'s unexpected elf data 0x%d\n", path, elf->e_ident[EI_DATA]);
      exit(1);
    }
    if (elf->e_ident[EI_OSABI] != ELFOSABI_FREEBSD) { /* freebsd */
      fprintf(stderr, "error: %'s unexpected elf abi 0x%d\n", path, elf->e_ident[EI_OSABI]);
      exit(1);
    }
    if (elf->e_type != ET_EXEC) { /* executable */
      fprintf(stderr, "error: %'s unexpected elf type 0x%d\n", path, elf->e_type);
      exit(1);
    }
    printf("main @ 0x%x\n", elf->e_entry);
  } else if (macho->magic == 0xFEEDFACF) {
    printf("found macho 64 header\n");
    if (mapsize < sizeof(*macho)) {
      fprintf(stderr, "error: %'s macho file too small\n", path);
      exit(1);
    }
    if (macho->filetype != MAC_EXECUTE) {
      fprintf(stderr, "error: %'s unexpected macho filetype 0x%d\n", path, macho->filetype);
      exit(1);
    }
    // should we bother checking main
  } else {
    fprintf(stderr, "error: %'s not a dos, elf or macho binary\n", path);
    exit(1);
  }
  munmap(map, mapsize);
  close(fd);
  return 0;
}
