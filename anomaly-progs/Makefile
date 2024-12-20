# Origin Source: https://github.com/Timothy-Liuxf/ebpf-examples/blob/master/Makefile

CXXFLAGS = -std=c++17 -O2 -Wall -Wpedantic -Wextra -Werror
PROGS = merge-sort merge-sort-leak
TARGETS = $(patsubst %,$(BUILD_DIR)/%,$(PROGS))
OBJECTS = $(patsubst %,%.o,$(TARGETS))
DEPS = $(patsubst %.o,%.d,$(OBJECTS))
BUILD_DIR ?= build
MKDIR = mkdir -p

$(shell $(MKDIR) $(BUILD_DIR))

.PHONY: all
all: $(TARGETS)
	:

$(TARGETS): %: %.o
	$(CXX) $(CXXFLAGS) -o $@ $^
$(OBJECTS): $(BUILD_DIR)/%.o: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -c $^
$(DEPS): $(BUILD_DIR)/%.d: %.cpp
	$(CXX) $(CXXFLAGS) -o $@ -MM $^

include $(DEPS)

.PHONY: clean
clean:
	-$(RM) -r $(BUILD_DIR)
