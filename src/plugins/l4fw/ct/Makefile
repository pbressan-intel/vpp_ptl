CC=gcc
VPP_ROOT=../../../..

all: check run

test: l4fw_ct_test

run: l4fw_ct_test
	./l4fw_ct_test -x

# Build the unit test code
l4fw_ct_test: l4fw_ct_test.c l4fw_ct_internal.c l4fw_ct.h l4fw_ct_internal.h ../l4fw_utils.h ../l4fw_utils.c
	${CC} -g -o1 \
	-o l4fw_ct_test \
	-DL4FW_CT_TESTING \
	-I${VPP_ROOT}/build-root/install-vpp_debug-native/vpp/include/ -I${VPP_ROOT}/src -I${VPP_ROOT}/src/plugins \
	l4fw_ct_test.c l4fw_ct_internal.c ../l4fw_utils.c

# Run it through valgrind
check: test
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./l4fw_ct_test && cat valgrind-out.txt

# Clean up
clean:
	rm -rf *.o l4fw_ct_test