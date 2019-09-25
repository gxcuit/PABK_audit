#pragma once
double chall_gen(Challenge *chall, int random_seeds, pairing_t pairing);
double my_proof_verify(Challenge chall, Proof p, const char * keyword, element_t pk, pairing_t pairing);
