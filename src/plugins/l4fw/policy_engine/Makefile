CC=gcc
VPP_ROOT=../../../..

all: check run

test: l4fw_policy_engine_test

run: l4fw_policy_engine_test
	./l4fw_policy_engine_test

# Build the unit test code
# Use -Wno-address-of-packed-member to ignore a warning from a VPP include
l4fw_policy_engine_test: l4fw_policy_engine_test.c l4fw_policy_engine.c l4fw_policy_engine.h ../l4fw_utils.h ../l4fw_utils.c
	${CC} -g -O3 \
	-o l4fw_policy_engine_test \
	-Wno-address-of-packed-member  \
	-DL4FW_POLICY_ENGINE_TESTING \
	-I${VPP_ROOT}/build-root/install-vpp_debug-native/vpp/include/ -I${VPP_ROOT}/src -I${VPP_ROOT}/src/plugins \
	l4fw_policy_engine_test.c l4fw_policy_engine.c ../l4fw_utils.c

# Run it through valgrind
check: test
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./l4fw_policy_engine_test && cat valgrind-out.txt

# Clean up
clean:
	rm -rf *.o l4fw_policy_engine_test valgrind-out.txt