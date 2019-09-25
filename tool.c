#include "tool.h"
void myprintf(element_t t) {
	element_printf("%B\n", t);
}

char* get_current_time() {
	time_t t;
	time(&t);
	char des[100] = { '\0' };
	char *ti = ctime(&t);
	return strncpy(des, ti, strlen(ti) - 1);
}