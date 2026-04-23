CC ?= cc
CFLAGS ?= -D_DEFAULT_SOURCE -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude

BUILD_DIR := build
LIB := $(BUILD_DIR)/liblha.a
CORE_OBJS := \
	$(BUILD_DIR)/lha_resolver.o \
	$(BUILD_DIR)/lha_json.o
TEST := $(BUILD_DIR)/test_resolver

.PHONY: all test clean

all: $(LIB)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/lha_resolver.o: src/lha_resolver.c include/lha_types.h include/lha_kernel_api.h include/lha_resolver.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/lha_json.o: src/lha_json.c include/lha_types.h include/lha_json.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(CORE_OBJS)
	ar rcs $@ $(CORE_OBJS)

$(BUILD_DIR)/test_resolver.o: tests/test_resolver.c include/lha_types.h include/lha_kernel_api.h include/lha_resolver.h include/lha_json.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST): $(LIB) $(BUILD_DIR)/test_resolver.o
	$(CC) $(CFLAGS) $(BUILD_DIR)/test_resolver.o $(LIB) -o $@

test: $(TEST)
	$(TEST)

clean:
	rm -rf $(BUILD_DIR)
