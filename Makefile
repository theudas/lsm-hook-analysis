CC ?= cc
CFLAGS ?= -Wall -Wextra -Werror -std=c11
USER_TARGET := hook_json_mock_demo

.PHONY: all user test clean

all: user

user: $(USER_TARGET)

$(USER_TARGET): hook_json_mock_demo.c
	$(CC) $(CFLAGS) -o $@ $<

test: user
	python3 -c 'import json, subprocess; print(json.loads(subprocess.check_output(["./$(USER_TARGET)"], text=True))["events"][0]["hook"])'

clean:
	rm -rf $(USER_TARGET) mock-fixtures
