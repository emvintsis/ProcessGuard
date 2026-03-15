#include "processguard.h"

int main() {
	CONTROLTRACE_ID tid;
	if (StartETWSession(&tid) != 0) return -1;
	return 0;
}