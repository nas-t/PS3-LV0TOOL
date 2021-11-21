#ifndef _UTIL_H_
#define _UTIL_H_

#include "types.h"


struct elf_phdr {
	uint32_t p_type;
	uint64_t p_off;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint32_t p_flags;
	uint64_t p_align;

	void *ptr;
};

struct elf_shdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint32_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint32_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
};


struct elf_hdr {
	char e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shtrndx;
};


uint32_t round_up(uint32_t x, uint32_t n);

int read_entire_file(const char *file_path, void **data, uint32_t *size, uint32_t roundup);
int read_file(const char *file_path, void *data, uint32_t size);
int write_file(const char *file_path, const void *data, uint32_t size);

void print_hex(const uint8_t *data, uint32_t size);

uint32_t swap32(uint32_t x);
uint32_t be32(uint8_t *p);
uint8_t be8(uint8_t *p);
uint16_t be16(uint8_t *p);
uint64_t be64(uint8_t *p);

int elf_read_hdr(uint8_t *hdr, struct elf_hdr *h);
void elf_read_phdr(int arch64, uint8_t *phdr, struct elf_phdr *p);
void elf_read_shdr(int arch64, uint8_t *shdr, struct elf_shdr *s);

uint32_t reverse_binsearch64(uint8_t * in, uint32_t size, uint64_t value);
uint32_t binsearch64(uint8_t * in, uint32_t size, uint64_t value);
uint8_t * set_data(uint8_t *in, uint32_t addr);
uint32_t ra_to_va(uint8_t *in, uint32_t ra);
uint32_t va_to_ra(uint8_t *in, uint32_t va);
uint32_t find_va_sh(unsigned int idx, uint32_t ra, uint8_t *in);
uint32_t find_ra_sh(unsigned int idx, uint32_t va, uint8_t *in);
uint32_t get_end_of_last_section(uint8_t *in);


#endif
