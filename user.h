#pragma once
#include "public_header.h"
/*
	计算一个文件f的所有（N个）认证器
	模拟文件f的每一个数据块f->data[i]；根据数据块计算对应的认证器f->authenticator[i]
	输入：MyFile *f (需要提前设置文件id：f->id)
	输出：MyFile *f（与输入相比，新增了：f->data[i]，f->authenticator[i]）0<=i<N-1
*/
double my_auth_gen(MyFile *f, element_t sk, pairing_t pairing);
/*
	计算这个keyword 对应的N（数据块的数量）个KeywordTag（每一个keyword对应NUM个文件）
	输入：KeywordTag *kt
		需要提前设置1）这个keyword的名字：keyword_tag.keyword
					2）这个keyword对应哪些（NUM个）文件（id）：keyword_tag.file_id
	输出：KeywordTag *kt （与输入相比，新增了tag[i]）0<=i<=N-1
*/
double my_keywordtag_gen(KeywordTag *kt, element_t sk, pairing_t pairing);