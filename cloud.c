#include "cloud.h"

double proof_gen(Proof *p, MyFile f[], Challenge chall, pairing_t pairing, KeywordTag t) {
	double t1 = pbc_get_time();
	element_t vi_mi, sigi_vi, tag_vi;
	element_init_Zr(vi_mi, pairing);
	element_init_G1(sigi_vi, pairing);
	element_init_Zr(p->agg_data, pairing);
	element_init_G1(p->agg_auth, pairing);
	element_init_G1(tag_vi, pairing);
	for (int i = 0; i < NUM; i++)
	{
		for (size_t j = 0; j < C; j++)
		{
			int index = chall.i[j];

			element_pow_zn(sigi_vi, f[i].authenticator[index], chall.vi[j]);
			element_mul(p->agg_auth, p->agg_auth, sigi_vi);

			element_mul(vi_mi, chall.vi[j], f[i].data[index]);

			element_add(p->agg_data, p->agg_data, vi_mi);
		}
	}
	for (size_t i = 0; i < C; i++)
	{
		int index = chall.i[i];
		element_pow_zn(tag_vi, t.tag[index], chall.vi[i]);
		element_mul(p->agg_auth, p->agg_auth, tag_vi);
	}

	//clear
	element_clear(vi_mi);
	element_clear(sigi_vi);
	element_clear(tag_vi);

	double t2 = pbc_get_time();
	return t2 - t1;
}