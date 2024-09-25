USR_TESTS := test-dummy_op test-mul_op test-class_op test-det_op test-seg_op

CPPFLAGS := -I.. -Wall
USR_CPPFLAGS := $(USR_CPPFLAGS)

tests: $(USR_TESTS)

test-%.o: test-%.c
	$(CC) $(USR_CFLAGS) ${CPPFLAGS} -o $@ -c $^
test-%_op: test-%_op.o test-common.o
	$(CC) $(USR_CFLAGS) ${CPPFLAGS} -o $@ $^

.PHONY: clean
clean:
	rm -f $(USR_TESTS)
