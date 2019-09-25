#pragma once
#include "public_header.h"
/*
	����һ���ļ�f�����У�N������֤��
	ģ���ļ�f��ÿһ�����ݿ�f->data[i]���������ݿ�����Ӧ����֤��f->authenticator[i]
	���룺MyFile *f (��Ҫ��ǰ�����ļ�id��f->id)
	�����MyFile *f����������ȣ������ˣ�f->data[i]��f->authenticator[i]��0<=i<N-1
*/
double my_auth_gen(MyFile *f, element_t sk, pairing_t pairing);
/*
	�������keyword ��Ӧ��N�����ݿ����������KeywordTag��ÿһ��keyword��ӦNUM���ļ���
	���룺KeywordTag *kt
		��Ҫ��ǰ����1�����keyword�����֣�keyword_tag.keyword
					2�����keyword��Ӧ��Щ��NUM�����ļ���id����keyword_tag.file_id
	�����KeywordTag *kt ����������ȣ�������tag[i]��0<=i<=N-1
*/
double my_keywordtag_gen(KeywordTag *kt, element_t sk, pairing_t pairing);