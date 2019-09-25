#pragma once
#include <pbc.h>
#include "pbc_test.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#define N 500
#define C 460
#define NUM 3


element_t g, sk, pk, u;// agg_hash;;// , agg_data, agg_auth, 
pairing_t pairing;

typedef struct
{
	element_t data[N], authenticator[N];
	char id[100];
}MyFile;

typedef struct
{
	element_t tag[N];
	char *keyword;
	char file_id[NUM][100];
}KeywordTag;

typedef struct
{
	int i[C];
	element_t vi[C];
}Challenge;

typedef struct
{
	element_t agg_data, agg_auth;
}Proof;

typedef struct
{
	element_t agg_data, agg_auth1, agg_auth2;
}LiuProof;
