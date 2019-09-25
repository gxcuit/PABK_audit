// pbcTest.cpp : �������̨Ӧ�ó������ڵ㡣
#include "tool.h"
#include "public_header.h"
#include "user.h"
#include "tpa.h"
#include "cloud.h"

MyFile f[NUM];
KeywordTag keyword_tag;
FILE *fp;

void init(int argc, char **argv) {
	//-----1.��ʼ�����ֲ���-----
//	pbc_demo_pairing_init(pairing, argc, argv);
	pbc_param_t param;
	pbc_param_init_a_gen(param,160,512);
	pairing_init_pbc_param(pairing, param);	
	//��ʼ��public_header�еĹ�������
	element_init_G1(u, pairing);
	element_init_G2(g, pairing);
	element_init_Zr(sk, pairing);
	element_init_G2(pk, pairing);
	element_random(g);
	element_random(u);
	//�����û���˽Կsk��Կpk
	element_random(sk);
	element_pow_zn(pk, g, sk);//��Կ

	//-----2.׼���ļ����������N��C��NUM������Ϣ-----
	fp = fopen("data.txt", "a+");
	//��ȡ��ǰʱ�䣬���ڴ�ӡlog
	time_t t;
	time(&t);
	char des[100] = { '\0' };
	char *ti = ctime(&t);
	strncpy(des, ti, strlen(ti) - 1);
	//��ӡlogʱ����Ϣ
	fprintf(fp, "INFO(%s) :\n", des);
	printf("INFO(%s) :\n", des);
	fprintf(fp, "pairing_length_in_bytes_Zr:%d ;G1:%d ;G2:%d ;GT:%d\n", pairing_length_in_bytes_Zr(pairing), pairing_length_in_bytes_G1(pairing), pairing_length_in_bytes_G2(pairing), pairing_length_in_bytes_GT(pairing));
	printf("pairing_length_in_bytes_Zr:%d ;G1:%d ;G2:%d ;GT:%d\n", pairing_length_in_bytes_Zr(pairing), pairing_length_in_bytes_G1(pairing), pairing_length_in_bytes_G2(pairing), pairing_length_in_bytes_GT(pairing));
	fprintf(fp, "The number of blocks in each file : %d\n", N);
	printf("The number of blocks in each file : %d\n", N);
	fprintf(fp, "The number of challenge blocks : %d\n", C);
	printf("The number of challenge blocks : %d\n", C);
	fprintf(fp, "The number of files related to the keyword : %d\n", NUM);
	printf("The number of files related to the keyword : %d\n", NUM);

	//-----3.ģ���ļ���Ϣ���������ļ�id���ļ����ݿ飩-----
	memset((void *)f, 0, sizeof(f));
	//1��keyword ��ӦNUM���ļ�
	for (int i = 0; i < NUM; i++)
	{
		sprintf(f[i].id, "This is the %d's file", i);
		for (size_t j = 0; j < N; j++)
		{
			element_init_Zr(f[i].data[j], pairing);
			element_random(f[i].data[j]);
			element_init_G1(f[i].authenticator[j], pairing);
		}
	}

	//-----4.ģ��keyword-----
	memset((void *)&keyword_tag, 0, sizeof(keyword_tag));
	keyword_tag.keyword = "keyword";
	//���keyword��Ӧ��Щ�ļ�����f[0]---f[NUM-1]���ļ������ؼ��֣�
	for (int i = 0; i < NUM; i++)
	{
		sprintf(keyword_tag.file_id[i], "This is the %d's file", i);
	}
}

void clear() {
	element_clear(u);
	element_clear(g);
	element_clear(sk);
	element_clear(pk);
	pairing_clear(pairing);
	fclose(fp);
}

int my_scheme(int argc, char **argv) {

	init(argc, argv);
	double tt1 = 0, tt2 = 0;

	//-----������֤����NUM*N����-----
	tt1 = pbc_get_time();
	for (size_t i = 0; i < NUM; i++)
	{
		my_auth_gen(&f[i], sk, pairing);
	}
	tt2 = pbc_get_time();
	fprintf(fp, "(1)Authenticator generation time for %d blocks and %d files is %f\n", N, NUM, tt2 - tt1);
	printf("(1)Authenticator generation time for %d blocks and %d files is %f\n", N, NUM, tt2 - tt1);
	tt2 = 0; tt1 = 0;

	//-----����keywordtag��NUM*N����-----
	tt1 = my_keywordtag_gen(&keyword_tag, sk, pairing);
	fprintf(fp, "(2)Keyword tag generation time for %d files and %d blocks is %f\n", NUM, N, tt1);
	printf("(2)Keyword tag generation time for %d files and %d blocks is %f\n", NUM, N, tt1);
	tt1 = 0;

	srand(time(NULL));
	int seeds = rand();
	Challenge chall;


	//-----����seeds����chall-----
	Proof p;
	tt1=chall_gen(&chall, seeds, pairing);
	fprintf(fp, "(3)Challenge generation time for %d checking-blocks is %f\n", C, tt1);
	printf("(3)Challenge generation time for %d checking-blocks is %f\n", C, tt1);
	tt1 = 0;

	//-----����proof-----
	tt1 = proof_gen(&p, f, chall, pairing, keyword_tag);
	fprintf(fp, "(4)Proof generation time for one keyword(contains %d files) and %d checking-blocks is %f\n", NUM, C, tt1);
	printf("(4)Proof generation time for one keyword(contains %d files) and %d checking-blocks is %f\n", NUM, C, tt1);
	tt1 = 0;

	//-----��֤proof-----
	tt1 = my_proof_verify(chall, p, "keyword", pk, pairing);
	if (tt1 > 0) {
		fprintf(fp, "(5)Proof verifacation time for %d checking-blocks is %f\n", C, tt1);
		printf("(5)Proof verifacation time for %d checking-blocks is %f\n", C, tt1);
		fprintf(fp, "-----valid!-----\n \n");
		printf("-----valid!-----\n \n");
	}
	else {
		fprintf(fp, "-----invalid!-----\n \n");
		printf("-----invalid!-----\n \n");
	}

	clear();
	return 0;
}


//int my_scheme2(int argc, char **argv) {
//
//	init(argc, argv);
//	double tt = 0, tt2 = 0;
//
//	//�ļ�����
//	FILE *fp = fopen("log_my_scheme.txt", "a+");
//	//��ȡ��ǰʱ�䣬���ڴ�ӡlog
//	time_t t;
//	time(&t);
//	char des[100] = { '\0' };
//	char *ti = ctime(&t);
//	strncpy(des, ti, strlen(ti) - 1);
//	//��ӡlogʱ����Ϣ
//	fprintf(fp, "INFO(%s) :\n", des);
//	printf("INFO(%s) :\n", des);
//
//	//�Լ�Э�����õ���sk_f,pk_f,pk_uf
//	element_t pk_uf, sk_f, pk_f;
//	element_init_Zr(sk_f, pairing);
//	element_init_G1(pk_uf, pairing);
//	element_init_G1(pk_f, pairing);
//
//	//---�����ļ�---
//	MyFile f;
//	f.id = "This is the i'th file";//ģ���ļ���id����һ��������Ӱ�첻��
//
//	//tag key gen
//	tt = my_tagkey_gen(sk_f, pk_f, f.id, pairing);
//	//��ӡ tag key ����ʱ��
//	fprintf(fp, "(1)tag_key__gen_time is %f\n", tt);
//	printf("(1)tag_key__gen_time is %f\n", tt);
//	tt = -1000;
//
//	//re key gen
//	tt = my_rekey_gen(pk_uf, pk_f, sk, pairing);
//	//��ӡ tag key ����ʱ��
//	fprintf(fp, "(2)re_key__gen_time is %f\n", tt);
//	printf("(2)re_key__gen_time is %f\n", tt);
//	tt = -1000;
//
//	//���ɱ�ǩ
//	tt = my_auth_gen(&f, sk_f, pairing);
//	//��ӡ tag ����ʱ��
//	fprintf(fp, "(3)auth_gen_time for %d blocks is %f\n", N, tt);
//	printf("(3)auth_gen_time for %d blocks is %f\n", N, tt);
//	tt = -1000;
//
//	//---����challenge---
//	//����ֻ����seeds
//	srand(time(NULL));
//	int seeds = rand();
//	Challenge chall;
//
//
//	//����proof��Ҫ�ȸ���seeds����chall
//	Proof p;
//	tt = chall_gen(&chall, seeds, pairing);
//	//tt2 = proof_gen(&p, f, chall, pairing);
//	//��ӡ proof ����ʱ��
//	fprintf(fp, "(4)proof_gen_time for %d checking-blocks is %f\n", C, tt2);
//	printf("(4)proof_gen_time for %d checking-blocks is %f\n", C, tt2);
//	tt = -1000;
//	tt2 = -1000;
//
//	//��֤proof��Ҫ�ȸ���seeds����chall
//	memset(&chall, 0, sizeof(chall));
//	tt = chall_gen(&chall, seeds, pairing);
//	//tt2 = my_proof_verify(chall, p, f.id, pk, pk_uf, pairing);
//	if (tt2 == -1) {
//		//��֤ʧ��
//		fprintf(fp, "not valid!\n-----failed!-----\n");
//		printf("not valid!\n-----failed-----\n");
//		return -1;
//	}
//	//��ӡ proof ��֤ʱ��
//	fprintf(fp, "(5)proof_verifacation_time for %d cheching-blocks is %f\n-----individual auditing valid!-----\n", C, tt + tt2);
//	printf("(5)proof_verifacation_time for %d checking-blocks is %f\n-----individual auditing valid-----\n", C, tt + tt2);
//	tt = -1000;
//	tt2 = -1000;
//
//	//batch auditing
//	memset(&chall, 0, sizeof(chall));
//	tt2 = chall_gen(&chall, seeds, pairing);
//	element_t sk_set[TASK], pk_set[TASK], pk_uf_set[TASK];
//	for (size_t i = 0; i < TASK; i++)
//	{
//		element_init_Zr(sk_set[i], pairing);
//		element_init_G1(pk_set[i], pairing);
//		element_init_G1(pk_uf_set[i], pairing);
//
//		element_random(sk_set[i]);
//		element_pow_zn(pk_set[i], g, sk_set[i]);
//		element_pow_zn(pk_uf_set[i], pk_f, sk_set[i]);
//	}
////	tt = my_proof_batch_auditing(chall, p, f.id, pk_set, pk_uf_set, pairing, TASK);
//	if (tt == -1) {
//		//��֤ʧ��
//		fprintf(fp, "not valid!\n-----failed!-----\n");
//		printf("not valid!\n-----failed-----\n");
//		return -1;
//	}
//	fprintf(fp, "(6)batch auditing time for %d TASK is %f\n-----batch auditing valid!-----\n", TASK, tt + tt2);
//	printf("(6)batch auditing time for %d TASK is %f\n-----batch auditing valid!-----\n", TASK, tt + tt2);
//	tt = -1000;
//	tt2 = -1000;
//
//	//�Լ�Э���Զ���clear
//	element_clear(pk_uf);
//	element_clear(sk_f);
//	element_clear(pk_f);
//	//file ��challclear
//	for (size_t i = 0; i < N; i++)
//	{
//		element_clear(f.data[i]);
//		element_clear(f.authenticator[i]);
//	}
//	for (size_t i = 0; i < C; i++)
//	{
//		element_clear(chall.vi[i]);
//	}
//	//��������clear
//	clear();
//	fclose(fp);
//	return 0;
//}




///*
//��ͳ��bls
//*/
//int bls(int argc, char **argv) {
//	pairing_t pairing;
//	pbc_demo_pairing_init(pairing, argc, argv);
//	element_t g, h, sk, pk, sig, temp1, temp2, m, u_m, u;
//	element_init_G1(sig, pairing);
//	element_init_G1(h, pairing);
//	element_init_G1(u, pairing);
//	element_init_G1(u_m, pairing);
//	element_init_G2(g, pairing);
//	element_init_Zr(sk, pairing);
//	element_init_Zr(m, pairing);
//	element_init_G2(pk, pairing);
//	element_init_GT(temp1, pairing);//��������e�Ƚϵģ���ʽ�����
//	element_init_GT(temp2, pairing);//��ʽ�ұ�
//	element_random(sk);
//	element_random(g);
//	element_random(u);
//	element_random(m);
//	element_pow_zn(pk, g, sk);//��Կ
//	element_from_hash(h, (char *)"id || i", sizeof("id||i"));//hash()
//	element_pow_zn(u_m, u, m);//u^m
//	element_mul(h, h, u_m);//hash()*u^m
//	element_pow_zn(sig, h, sk);//[]^sk =>signature
//	element_t tag, b, keyword;
//	element_init_G1(tag, pairing);
//	element_init_G1(b, pairing);
//	element_init_G1(keyword, pairing);
//	element_invert(h, h);
//	element_mul(tag, tag, h);
//	element_from_hash(b, (char *)"i", sizeof("i"));
//	element_mul(tag, tag, b);
//	element_from_hash(keyword, (char *)"keyword||i", sizeof("keyword||i"));
//	element_mul(tag, tag, keyword);
//	element_pow_zn(tag, tag, sk);
//	double t1 = pbc_get_time();
//	element_mul(sig, sig, tag);
//	pairing_apply(temp1, sig, g, pairing);
//	element_mul(b, b, keyword);
//	element_mul(b, b, m);
//	pairing_apply(temp2, h, pk, pairing);
//	printf("%d   ", element_cmp(temp1, temp2));
//	double t2 = pbc_get_time();
//	printf("time=%f", t2 - t1);
//	return 0;
//}

void time_test(int argc, char **argv) {
	pbc_demo_pairing_init(pairing, argc, argv);
	element_t ele_Z, ele_G1;
	element_init_Zr(ele_Z, pairing);
	element_init_G1(ele_G1, pairing);
	element_random(ele_Z);
	element_random(ele_G1);
	double t1,t2; 

	t1 = pbc_get_time();
	for (size_t i = 0; i < 1000; i++)
	{
		element_from_hash(ele_Z, "aaaaa", strlen("aaaaa"));
	}
	t2 = pbc_get_time();
	printf("1000 times hash operation in Zr is %f\n",t2-t1);

	t1 = pbc_get_time();
	for (size_t i = 0; i < 1000; i++)
	{
		element_from_hash(ele_G1, "aaaaa", strlen("aaaaa"));
	}
	t2 = pbc_get_time();
	printf("1000 times hash operation in G1 is %f\n", t2 - t1);

	t1 = pbc_get_time();
	for (size_t i = 0; i < 1000; i++)
	{
		element_pow_zn(ele_G1, ele_G1, ele_Z);
	}
	t2 = pbc_get_time();
	printf("1000 times modular power operation in G1 is %f\n", t2 - t1);

 }


int main(int argc, char **argv)
{
	my_scheme(argc, argv);
	//time_test(argc, argv);
}
