#pragma once
#include "public_header.h"
/*
	����proof
	���룺proof��ʲô�������ã���chall����ѯC�����ݿ飩���ļ�����f����Ӧ��ѯ�ؼ��֣���KeywordTag t
	�����proof��agg_data, agg_auth;��
*/
double proof_gen(Proof *p, MyFile f[], Challenge chall, pairing_t pairing, KeywordTag t);