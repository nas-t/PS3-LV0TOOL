#include "util.h"

uint32_t round_up(uint32_t x, uint32_t n) {
	return (uint32_t)((x + n - 1) / n) * n;
}

int read_entire_file(const char *file_path, void **data, uint32_t *size, uint32_t roundup) {
	FILE *fp;
	struct stat st;
	void *ptr;
	uint32_t length;

	if (stat(file_path, &st) != -1)
		length = st.st_size;
	else {
		*data = NULL;
		*size = 0;
		return -EFAULT;
	}

	ptr = malloc(round_up(length, roundup));

	fp = fopen(file_path, "rb");
	if (!fp)
		return -EFAULT;
	fread(ptr, 1, length, fp);
	fclose(fp);

	*data = ptr;
	*size = length;

	return 0;
}

int read_file(const char *file_path, void *data, uint32_t size) {
	FILE *fp;
	fp = fopen(file_path, "rb");
	if (!fp)
		return -EFAULT;
	fread(data, 1, size, fp);
	fclose(fp);
	return 0;
}

int write_file(const char *file_path, const void *data, uint32_t size) {
	FILE *fp;
	fp = fopen(file_path, "wb");
	if (!fp)
		return -EFAULT;
	fwrite(data, 1, size, fp);
	fclose(fp);
	return 0;
}

void print_hex(const uint8_t *data, uint32_t size) {
	uint32_t i;
	for (i = 0; i < size; ++i)
		printf("%02X ", data[i]);
	printf("\n");
}

uint32_t swap32(uint32_t x) {
    x = ((x << 8) & 0xFF00FF00) | ((x >> 8) & 0xFF00FF);
    return (x << 16) | (x >> 16);
}

uint32_t be32(uint8_t *p)
{
	uint32_t a;

	a  = p[0] << 24;
	a |= p[1] << 16;
	a |= p[2] <<  8;
	a |= p[3] <<  0;

	return a;
}


uint8_t be8(uint8_t *p)
{
	return *p;
}

uint16_t be16(uint8_t *p)
{
	uint16_t a;

	a  = p[0] << 8;
	a |= p[1];

	return a;
}


uint64_t be64(uint8_t *p)
{
	uint32_t a, b;

	a = be32(p);
	b = be32(p + 4);

	return ((uint64_t)a<<32) | b;
}



int elf_read_hdr(uint8_t *hdr, struct elf_hdr *h)
{
	int arch64;
	memcpy(h->e_ident, hdr, 16);
	hdr += 16;

	arch64 = h->e_ident[4] == 2;

	h->e_type = be16(hdr);
	hdr += 2;
	h->e_machine = be16(hdr);
	hdr += 2;
	h->e_version = be32(hdr);
	hdr += 4;

	if (arch64) {
		h->e_entry = be64(hdr);
		h->e_phoff = be64(hdr + 8);
		h->e_shoff = be64(hdr + 16);
		hdr += 24;
	} else {
		h->e_entry = be32(hdr);
		h->e_phoff = be32(hdr + 4);
		h->e_shoff = be32(hdr + 8);
		hdr += 12;
	}

	h->e_flags = be32(hdr);
	hdr += 4;

	h->e_ehsize = be16(hdr);
	hdr += 2;
	h->e_phentsize = be16(hdr);
	hdr += 2;
	h->e_phnum = be16(hdr);
	hdr += 2;
	h->e_shentsize = be16(hdr);
	hdr += 2;
	h->e_shnum = be16(hdr);
	hdr += 2;
	h->e_shtrndx = be16(hdr);

	return arch64;
}


void elf_read_phdr(int arch64, uint8_t *phdr, struct elf_phdr *p)
{
	if (arch64) {
		p->p_type =   be32(phdr + 0);
		p->p_flags =  be32(phdr + 4);
		p->p_off =    be64(phdr + 1*8);
		p->p_vaddr =  be64(phdr + 2*8);
		p->p_paddr =  be64(phdr + 3*8);
		p->p_filesz = be64(phdr + 4*8);
		p->p_memsz =  be64(phdr + 5*8);
		p->p_align =  be64(phdr + 6*8);
	} else {
		p->p_type =   be32(phdr + 0*4);
		p->p_off =    be32(phdr + 1*4);
		p->p_vaddr =  be32(phdr + 2*4);
		p->p_paddr =  be32(phdr + 3*4);
		p->p_filesz = be32(phdr + 4*4);
		p->p_memsz =  be32(phdr + 5*4);
		p->p_flags =  be32(phdr + 6*4);
		p->p_align =  be32(phdr + 7*4);
	}
}

void elf_read_shdr(int arch64, uint8_t *shdr, struct elf_shdr *s)
{
	if (arch64) {
		s->sh_name =	  be32(shdr + 0*4);
		s->sh_type =	  be32(shdr + 1*4);
		s->sh_flags =	  be64(shdr + 2*4);
		s->sh_addr =	  be64(shdr + 2*4 + 1*8);
		s->sh_offset =	  be64(shdr + 2*4 + 2*8);
		s->sh_size =	  be64(shdr + 2*4 + 3*8);
		s->sh_link =	  be32(shdr + 2*4 + 4*8);
		s->sh_info =	  be32(shdr + 3*4 + 4*8);
		s->sh_addralign = be64(shdr + 4*4 + 4*8);
		s->sh_entsize =   be64(shdr + 4*4 + 5*8);
	} else {
		s->sh_name =	  be32(shdr + 0*4);
		s->sh_type =	  be32(shdr + 1*4);
		s->sh_flags =	  be32(shdr + 2*4);
		s->sh_addr =	  be32(shdr + 3*4);
		s->sh_offset =	  be32(shdr + 4*4);
		s->sh_size =	  be32(shdr + 5*4);
		s->sh_link =	  be32(shdr + 6*4);
		s->sh_info =	  be32(shdr + 7*4);
		s->sh_addralign = be32(shdr + 8*4);
		s->sh_entsize =   be32(shdr + 9*4);
	}
}



uint32_t get_end_of_last_section(uint8_t *in)
{
	struct elf_hdr ehdr;
	struct elf_shdr s;
	int arch64 = elf_read_hdr(in, &ehdr);

	elf_read_shdr(arch64, in + ehdr.e_shoff + (ehdr.e_shentsize * (ehdr.e_shnum-3)), &s);

	return (uint32_t)(s.sh_offset + s.sh_size);
}


uint32_t find_ra_sh(unsigned int idx, uint32_t va, uint8_t *in)
{
	struct elf_hdr ehdr;
	struct elf_shdr s;
	int arch64 = elf_read_hdr(in, &ehdr);

	elf_read_shdr(arch64, in + ehdr.e_shoff + (ehdr.e_shentsize * idx), &s);

	if (arch64)
	{
		//printf("sh: %x-%x\n", (uint32_t)s.sh_addr, (uint32_t)s.sh_size+(uint32_t)s.sh_addr);
		if(((uint32_t)s.sh_size+(uint32_t)s.sh_addr)>va && (((uint32_t)s.sh_addr)<va || ((uint32_t)s.sh_addr)==va))
			return (va-(uint32_t)s.sh_addr)+(uint32_t)s.sh_offset;
		else
			return 0;
	}else{
		return 0;
	}
}

uint32_t find_va_sh(unsigned int idx, uint32_t ra, uint8_t *in)
{
	struct elf_hdr ehdr;
	struct elf_shdr s;
	int arch64 = elf_read_hdr(in, &ehdr);

	elf_read_shdr(arch64, in + ehdr.e_shoff + (ehdr.e_shentsize * idx), &s);

	if (arch64)
	{
		if(((uint32_t)s.sh_size+(uint32_t)s.sh_offset)>ra && ((uint32_t)s.sh_offset-1)<ra)
			return (ra-(uint32_t)s.sh_offset)+(uint32_t)s.sh_addr;
		else
			return 0;
	}else{
		return 0;
	}
}


uint32_t va_to_ra(uint8_t *in, uint32_t va)
{

	struct elf_hdr ehdr;
	elf_read_hdr(in, &ehdr);

	unsigned int i, result;
	if (ehdr.e_shnum > 0)
	{
		for (i = 0; i < ehdr.e_shnum; i++)
		{
			result = find_ra_sh(i, va, in);
			if(result)
				return result;
	    }
	}

	return 0;
}


uint32_t ra_to_va(uint8_t *in, uint32_t ra)
{

	struct elf_hdr ehdr;
	elf_read_hdr(in, &ehdr);

	unsigned int i, result;
	if (ehdr.e_shnum > 0)
	{
		for (i = 0; i < ehdr.e_shnum; i++)
		{
			result = find_va_sh(i, ra, in);
			if(result)
				return result;
	    }
	}

	return 0;
}

uint8_t * set_data(uint8_t *in, uint32_t addr)
{
	uint32_t ra = va_to_ra(in, addr);
	//printf("va2ra: %x->%x\n", addr, ra);
	return in + ra;
}


uint32_t binsearch64(uint8_t * in, uint32_t size, uint64_t value)
{
	uint32_t i;

	for(i = 0; i < size; i += 8)
	{
		if(be64(in + i) == value)
		{
			//printf("found: %llx == %llx %x\n", be64(in + i), value, i);
			return i;
		}
	}

	return 0;
}

uint32_t reverse_binsearch64(uint8_t * in, uint32_t size, uint64_t value)
{
	uint32_t i = size - 8 - (size % 8);

	while(i > 0)
	{
		if(be64(in + i) == value)
		{
			//printf("found: %llx == %llx %x\n", be64(in + i), value, i);
			return i;
		}

		i -= 8;
	}

	return 0;
}