#include "user.h"

/*
@manucl
��������ļ�block����sk���ɱ�ǩauthenticator��������f�У�
*/

double my_auth_gen(MyFile *f, element_t sk, pairing_t pairing) {
	double t1 = pbc_get_time();
	//f->id = "file's ID";//ģ���ļ���id����һ��������Ӱ�첻��
	element_t h1, u_m;
	element_init_G1(h1, pairing);
	element_init_G1(u_m, pairing);
	for (int i = 0; i < N; i++)
	{
		//�����ļ�
		//element_init_Zr(f->data[i], pairing);
		//element_random(f->data[i]);
		////������֤��
		//element_init_G1(f->authenticator[i], pairing);
		//��hash��id||i��
		char buf[1000] = { '\0' };
		sprintf(buf, "%d", i);
		strcat(buf, "||");
		strcat(buf, f->id);
		element_from_hash(h1, (char *)buf, strlen(buf));
		element_pow_zn(u_m, u, f->data[i]);//u^m
		element_mul(h1, h1, u_m);//hash()*u^m
		element_pow_zn(f->authenticator[i], h1, sk);//[]^sk =>signature
	}
	element_clear(h1);
	element_clear(u_m);
	double t2 = pbc_get_time();
	return t2 - t1;

}
double my_keywordtag_gen(KeywordTag *kt, element_t sk, pairing_t pairing) {
	double t1 = pbc_get_time();
	element_t h1, h3, h2;
	element_init_G1(h1, pairing);
	element_init_G1(h3, pairing);
	element_init_G1(h2, pairing);
	// ��ÿһ����
	for (int i = 0; i < N; i++) {
		element_init_G1(kt->tag[i], pairing);
		//��ÿһ��id,��id���۳�
		for (int j = 0; j < NUM; j++) {
			char buf[1000] = { '\0' };
			sprintf(buf, "%d", i);
			strcat(buf, "||");
			strcat(buf, kt->file_id[j]);
			element_from_hash(h1, (char *)buf, strlen(buf));
			element_invert(h1, h1);
			element_mul(kt->tag[i], kt->tag[i], h1);
		}
		char buf2[1000] = { '\0' };
		sprintf(buf2, "%d", i);
		element_from_hash(h3, (char *)buf2, strlen(buf2));
		element_mul(kt->tag[i], kt->tag[i], h3);
		strcat(buf2, "||");
		strcat(buf2, kt->keyword);
		element_from_hash(h2, (char *)buf2, strlen(buf2));
		element_mul(kt->tag[i], kt->tag[i], h2);
		element_pow_zn(kt->tag[i], kt->tag[i], sk);
	}
	element_clear(h1);
	element_clear(h3);
	element_clear(h2);
	double t2 = pbc_get_time();
	return t2 - t1;
}