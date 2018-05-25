#include "c_json.h"
#include <stdio.h>

int main(int argc, char * argv[]) {
	char buf[] = "[{\"id\":1,\"first_name\":\"Jeanette\",\"last_name\":\"Penddreth\",\"email\":\"jpenddreth0@census.gov\",\"gender\":\"Female\",\"ip_address\":\"26.58.193.2\"}]";

	/*
	size_t bufsize = 1023;
	char * buf = (char *)malloc(bufsize+1);
	size_t bytes_read = fread((void *)buf, 1, bufsize, stdin);
	buf[bytes_read] = 0;
	*/

	struct c_json_value value0;
	if (!c_json_parse_text(&value0, buf, NULL, 0, true))
		return !!puts("Failed at #0");
	c_json_free_tree(&value0);

	struct c_json_value * value1 = c_json_parse_text_ptr(
		buf, NULL, 0, true
	);
	if (!value1)
		return !!puts("Failed at #1");
	c_json_free_tree(value1);
	free((void *)value1);

	// segfault me!
	// #define OBJ_COUNT (30)
	// char mem[OBJ_COUNT * sizeof(struct c_json_value)];
	// struct c_json_value value2;
	// if (!c_json_parse_text(&value2, buf, mem, 30, false))
	// 	return !!puts("failed at #2");


	return 0;
}
