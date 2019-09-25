#include "public_header.h"

double chall_gen(Challenge *chall, int random_seeds, pairing_t pairing) {
	double t1 = pbc_get_time();
	srand(random_seeds);
	for (size_t i = 0; i < C; i++)
	{
		chall->i[i] = rand() % N;
		element_init_Zr(chall->vi[i], pairing);
		element_set_si(chall->vi[i], rand());
	}
	double t2 = pbc_get_time();
	return t2 - t1;
}

double my_proof_verify(Challenge chall, Proof p, const char * keyword, element_t pk, pairing_t pairing) {
	double t1 = pbc_get_time();
	element_t h3, mul_h, h2, u_pow, temp1, temp2;
	element_init_G1(h3, pairing);
	element_init_G1(h2, pairing);
	element_init_G1(mul_h, pairing);
	element_init_G1(u_pow, pairing);
	element_init_GT(temp1, pairing);
	element_init_GT(temp2, pairing);
	for (size_t i = 0; i < C; i++)
	{
		int index = chall.i[i];
		char b[1000] = { '\0' };
		sprintf(b, "%d", index);
		element_from_hash(h3, (char *)b, strlen(b));//h3()
		strcat(b, "||");
		strcat(b, keyword);
		element_from_hash(h2, (char *)b, strlen(b));//h2()

		element_mul(h3, h3, h2);//h3()*h2()
		element_pow_zn(h3, h3, chall.vi[i]);//()^vb

		element_mul(mul_h, mul_h, h3);
	}

	element_pow_zn(u_pow, u, p.agg_data);
	element_mul(mul_h, mul_h, u_pow);

	pairing_apply(temp1, p.agg_auth, g, pairing);
	pairing_apply(temp2, mul_h, pk, pairing);

	if (element_cmp(temp1, temp2) != 0) {
		return -1000;
	}
	element_clear(h3);
	element_clear(mul_h);
	element_clear(h2);
	element_clear(u_pow);
	element_clear(temp1);
	element_clear(temp2);
	double t2 = pbc_get_time();
	return t2 - t1;
}
