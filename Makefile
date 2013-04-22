CC ?= gcc
SRC_DIR ?= src
BUILD_DIR ?= build
EXE ?= bismark-passive.bin
TEST_EXE ?= tests
HASHER_EXE ?= bismark-passive-hasher
CFLAGS += -c -Wall -O3 -fno-strict-aliasing
LDFLAGS += -lpcap -lresolv -lz

ifdef BUILD_ID
CFLAGS += -DBUILD_ID="\"$(BUILD_ID)\""
endif
ifdef DISABLE_ANONYMIZATION
CFLAGS += -DDISABLE_ANONYMIZATION
endif
ifdef USE_TEMP_SEED
CFLAGS += -DANONYMIZATION_SEED_FILE="\"/tmp/passive.key\""
endif
ifdef USE_TEMP_ID
CFLAGS += -DBISMARK_ID_FILENAME="\"/tmp/bismark.id\""
endif
ifdef USE_TEMP_WHITELIST
CFLAGS += -DDOMAIN_WHITELIST_FILENAME="\"/tmp/domain-whitelist.txt\""
endif
ifdef UPDATE_INTERVAL
CFLAGS += -DUPDATE_PERIOD_SECONDS="$(UPDATE_INTERVAL)"
endif
ifdef FREQUENT_UPDATES
CFLAGS += -DENABLE_FREQUENT_UPDATES
endif
ifdef DISABLE_FLOW_THRESHOLDING
CFLAGS += -DDISABLE_FLOW_THRESHOLDING
endif
ifdef ENABLE_HTTP_URL
CFLAGS += -DENABLE_HTTP_URL
endif

SRCS = \
	$(SRC_DIR)/address_table.c \
	$(SRC_DIR)/anonymization.c \
	$(SRC_DIR)/device_throughput_table.c \
	$(SRC_DIR)/dns_parser.c \
	$(SRC_DIR)/dns_table.c \
	$(SRC_DIR)/http_parser.c \
	$(SRC_DIR)/http_table.c \
	$(SRC_DIR)/drop_statistics.c \
	$(SRC_DIR)/flow_table.c \
	$(SRC_DIR)/main.c \
	$(SRC_DIR)/packet_series.c \
	$(SRC_DIR)/sha1.c \
	$(SRC_DIR)/upload_failures.c \
	$(SRC_DIR)/util.c \
	$(SRC_DIR)/whitelist.c
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

TEST_SRCS = \
	$(SRC_DIR)/address_table.c \
	$(SRC_DIR)/anonymization.c \
	$(SRC_DIR)/dns_parser.c \
	$(SRC_DIR)/dns_table.c \
	$(SRC_DIR)/flow_table.c \
	$(SRC_DIR)/packet_series.c \
	$(SRC_DIR)/sha1.c \
	$(SRC_DIR)/tests.c \
	$(SRC_DIR)/util.c \
	$(SRC_DIR)/whitelist.c
TEST_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(TEST_SRCS))

HASHER_SRCS = \
	src/anonymization.c \
	src/hasher.c \
	src/sha1.c \
	src/util.c
HASHER_OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(HASHER_SRCS))

all: debug

release: CFLAGS += -O3 -DNDEBUG
release: $(EXE)

debug: CFLAGS += -g
debug: $(EXE)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $< -o $@

$(EXE): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

fixperms: $(EXE)
	chmod 700 $(EXE)
	sudo setcap cap_net_raw,cap_net_admin=eip $(EXE)

$(TEST_EXE): CFLAGS += -g -DTESTING
$(TEST_EXE): LDFLAGS += -lcheck
$(TEST_EXE): $(TEST_OBJS)
	$(CC) $(TEST_OBJS) $(LDFLAGS) -o $@
	./$(@)

hasher: $(HASHER_EXE)

$(HASHER_EXE): $(HASHER_OBJS)
	$(CC) $(HASHER_OBJS) $(LDFLAGS) -o $@

clean:
	rm -f $(OBJS) $(EXE) $(TEST_OBJS) $(TEST_EXE)
