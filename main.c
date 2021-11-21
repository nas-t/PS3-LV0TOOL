#include "crypt.h"
#include "util.h"
#include "tables.h"

void crypt_lv1ldr(uint8_t *in, uint32_t size, uint8_t *erk, uint8_t *riv) {
	sfc_context_t *ctx;
	uint32_t rounded_size;

	rounded_size = round_up(size, SFC_BLOCK_SIZE);

	ctx = sfc_create_context(erk, riv);
	if (ctx) {
		//sfc_process_data(ctx, in, out, rounded_size);
		sfc_process_data(ctx, in, in, rounded_size);
		sfc_destroy_context(ctx);
	}else{
		printf("ctx fail\n");
	}

	//return out;
}


void extract_ldrs(uint8_t *in, uint32_t size)
{
	uint32_t ldr_size, i;
	char name[255];
	int j = 1;

	for(i=0;i<size;i+=4)
	{
		if(be32(in+i) == 0x53434500)
		{
			if(j > 4)
				break;

			ldr_size = (uint32_t)(be64(in+i+0x10) + be64(in+i+0x18));
			printf("extracting ldr at %x size: %x bytes\n", i, ldr_size);
			sprintf(name, "ldr_%i", j);
			write_file(name, in+i, ldr_size);
			j++;
		}
	}
}


void import_ldrs(uint8_t *in, uint32_t size)
{
	uint32_t ldr_size, import_size, i;
	uint8_t *ldr;
	char name[255];
	int j = 1;

	for(i=0;i<size;i+=4)
	{
		if(be32(in+i) == 0x53434500)
		{
			if(j > 4)
				break;

			sprintf(name, "ldr_%i", j);
			ldr_size = (uint32_t)(be64(in+i+0x10) + be64(in+i+0x18));
			if (read_entire_file(name, (void **)&ldr, &import_size, SFC_BLOCK_SIZE) < 0) {
				perror("read_file failed");
			}
			if(ldr_size == import_size && be64(in+i+0x70) == be64(ldr+0x70))
			{
				printf("importing ldr at %x size: %x bytes\n", i, ldr_size);
				memcpy(in+i, ldr, ldr_size);
			}else{
				printf("import failed: file does not match: %s\n\tsize:%x expected:%x\n\t auth id: %llx expected: %llx\n", name, import_size, ldr_size, be64(ldr+0x70), be64(in+i+0x70));
				exit(1);
			}

			j++;
		}
	}
}


uint8_t * get_lv1ldr(uint8_t * in, uint32_t size)
{
	uint32_t lv1ldr_ptr = binsearch64(in, size, 0x1800000000ULL) + 0xC;
	return in + lv1ldr_ptr;
}

uint32_t get_lv1ldr_size(uint8_t * in, uint32_t size, uint32_t addr)
{
	uint32_t va = ra_to_va(in, addr);
	//printf("va %x\n", va);
	uint32_t ptr_lv1ldr = reverse_binsearch64(in, size, va);
	//printf("lv1ldr_ptr %x->\n", ptr_lv1ldr, ra_to_va(in, ptr_lv1ldr));
	return (uint32_t) be64(in + ptr_lv1ldr + 8);
}


int main(int argc, char *argv[]) {

	uint8_t *erk;
	uint8_t *riv;
	uint8_t *in;
	uint8_t *lv1ldr;
	uint32_t lv1ldr_size;
	uint32_t end_of_data;
	uint32_t size;

	if (argc < 3) {
		printf("usage: lv0tool <option> lv0.elf [out]\n\noptions:\n\t-extract\n\t-import");
		exit(0);
	}

	//load lv0.elf
	if (read_entire_file(argv[2], (void **)&in, &size, SFC_BLOCK_SIZE) < 0) {
		perror("read_file");
	}else if(be32(in) != 0x7f454c46){
		printf("FAIL: %s is not an elf file\n", argv[2]);
		exit(1);
	}

	//find keys/data for lv1ldr crypto
	erk = set_data(in, 0x108);
	riv = set_data(in, 0x1B8);

	end_of_data = get_end_of_last_section(in);

	T1 = set_data(in, be64(in + end_of_data - 0x18));
	B = (uint32_t *) set_data(in, be64(in + end_of_data - 0x10));
	T2 = set_data(in, be64(in + end_of_data - 0x8));

	//find lv1ldr
	lv1ldr = get_lv1ldr(in, size);
	lv1ldr_size = get_lv1ldr_size(in, size, (uint32_t)(lv1ldr - in));

	/*print_hex(erk, 0x10);
	print_hex(riv, 0x10);
	print_hex(T1, 0x10);
	print_hex(B, 0x10);
	print_hex(T2, 0x10);
	print_hex(lv1ldr, 0x10);
	printf("lv1ldr_size %x\n", lv1ldr_size);*/

	//decrypt lv1ldr
	crypt_lv1ldr(lv1ldr, lv1ldr_size, erk, riv);

	//check decrypted lv1ldr
	if(be32(lv1ldr) != 0x53434500)
	{
		printf("(de)crypt_lv1ldr failed\n");
		exit(1);
	}

	if(strcmp(argv[1], "-extract") == 0 && argc > 2)
	{
		//extract
		extract_ldrs(in, size);
	}
	else if(strcmp(argv[1], "-import") == 0 && argc > 3)
	{
		//import and re-encrypt
		import_ldrs(in, size);
		crypt_lv1ldr(lv1ldr, lv1ldr_size, erk, riv);
		write_file(argv[3], in, size);

	}
	else
	{
		printf("FAIL: unknown option or missing parameter\n");
		exit(1);
	}

	free(in);

	return 0;
}