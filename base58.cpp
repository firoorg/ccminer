/*
 * Copyright 2012 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */
//#include <arpa/inet.h>
#ifdef __GNUC__
#include <arpa/inet.h>
#endif


#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <bosjansson.h>
//uint32_t htonla(uint32_t);

static const int8_t b58digits[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

static bool _blkmk_b58tobin(void *bin, size_t binsz, const char *b58, size_t b58sz)
{
	const unsigned char *b58u = (const unsigned char*)b58;
	unsigned char *binu = (unsigned char *)bin;
	const size_t outisz = ( ((size_t)26) + 3) / 4;
	uint32_t outi[outisz];
	uint64_t t;
	uint32_t c;
	size_t i, j;
	uint8_t bytesleft = binsz % 4;
	uint32_t zeromask = ~((1 << ((bytesleft) * 8)) - 1);

	if (!b58sz)
		b58sz = strlen(b58);

	memset(outi, 0, outisz * sizeof(*outi));

	for (i = 0; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return false;
		if (b58digits[b58u[i]] == -1)
			// Invalid base58 digit
			return false;
		c = b58digits[b58u[i]];
		for (j = outisz; j--; )
		{
			t = ((uint64_t)outi[j]) * 58 + c;
			c = (t & 0x3f00000000) >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return false;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return false;
	}

	j = 0;
	switch (bytesleft) {
		case 3:
			*(binu++) = (outi[0] &   0xff0000) >> 16;
		case 2:
			*(binu++) = (outi[0] &     0xff00) >>  8;
		case 1:
			*(binu++) = (outi[0] &       0xff);
			++j;
		default:
			break;
	}

	for (; j < outisz; ++j)
	{
//MSVC
#ifdef _MSC_VER 		
		*((uint32_t*)binu) = _byteswap_ulong(outi[j]);
#elif __GNUC__
		*((uint32_t*)binu) = htonl(outi[j]);
#endif		
		binu += sizeof(uint32_t);
	}
	return true;
}

extern "C" bool base58_decode(const char *input, char *output)
{
	unsigned char output_bin[32] = { 0 };
	bool b = _blkmk_b58tobin(output_bin, 26, input, 0);
	output[0] = '\0';

	if(!b) return false;

	for(int i=2; i < 22; i++)
		sprintf(output+strlen(output), "%02x", output_bin[i]);

	return true;
}


#define TX_VALUE(v, s)	((unsigned int)(v>>s)&0xff)

extern "C" void encode_tx_value(char *encoded, json_int_t value)
{
	sprintf(encoded, "%02x%02x%02x%02x%02x%02x%02x%02x",
		TX_VALUE(value, 0), TX_VALUE(value, 8), TX_VALUE(value, 16), TX_VALUE(value, 24),
		TX_VALUE(value, 32), TX_VALUE(value, 40), TX_VALUE(value, 48), TX_VALUE(value, 56));
}

extern "C"  void job_pack_tx(char *data, json_int_t amount, char *key)
{
	int ol = strlen(data);
	char evalue[32];
	encode_tx_value(evalue, amount);

	sprintf(data + strlen(data), "%s", evalue);

//	sprintf(data + strlen(data), "1976a914%s88ac", key ? key : coind->script_pubkey);
	sprintf(data + strlen(data), "1976a914%s88ac", key );

}

