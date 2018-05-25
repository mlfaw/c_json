c_json.... another JSON parser in C.... **terrible right?** I wouldn't use it if I were you..
===
Can be used to parse in-place while you stack-allocate `struct c_json_value`s (until it runs out and then it defaults to malloc()....), or it can just malloc values and duplicate strings...

**When parsing in place / with given `struct c_json_value`s it can currently get caught in a loop or just segfault... It messes up when closing arrays/objects somewhere... not going to put anymore time into debugging it since this shouldn't be used anywhere anyway...**

This doesn't parse escape sequences (\n, \", \u1234, etc) in strings (or anywhere else).

It can parse arrays or objects as the root value.

The main functions are at the top of `c_json.h`. In `main.c` are some examples of parsing JSON. Not any of iterating through for keys/values though...

**Really, you shouldn't use this.**
