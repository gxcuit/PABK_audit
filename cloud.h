#pragma once
#include "public_header.h"
/*
	生成proof
	输入：proof（什么都不设置）、chall（质询C个数据块）、文件集合f（对应查询关键字）、KeywordTag t
	输出：proof（agg_data, agg_auth;）
*/
double proof_gen(Proof *p, MyFile f[], Challenge chall, pairing_t pairing, KeywordTag t);