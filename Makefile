CC = gcc
CFLAGS += -c -Wall -O3 -fno-strict-aliasing
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
LDFLAGS += -lpcap -lresolv -lz
SRCS = \
	src/address_table.c \
	src/anonymization.c \
	src/device_throughput_table.c \
	src/dns_parser.c \
	src/dns_table.c \
	src/drop_statistics.c \
	src/flow_table.c \
	src/main.c \
	src/packet_series.c \
	src/sha1.c \
	src/util.c \
	src/whitelist.c
OBJS = $(SRCS:.c=.o)
EXE = bismark-passive.bin

TEST_SRCS = \
	src/address_table.c \
	src/anonymization.c \
	src/dns_parser.c \
	src/dns_table.c \
	src/flow_table.c \
	src/packet_series.c \
	src/tests.c \
	src/util.c \
	src/whitelist.c
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_EXE = tests

all: debug

release: CFLAGS += -O3 -DNDEBUG
release: $(EXE)

debug: CFLAGS += -g
debug: $(EXE)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@

fixperms: $(EXE)
	chmod 700 $(EXE)
	sudo setcap cap_net_raw,cap_net_admin=eip $(EXE)

$(TEST_EXE): CFLAGS += -g -DTESTING
$(TEST_EXE): LDFLAGS += -lcheck
$(TEST_EXE): $(TEST_OBJS)
	$(CC) $(LDFLAGS) $(TEST_OBJS) -o $@
	./$(@)

clean:
	rm -rf $(OBJS) $(EXE) $(TEST_OBJS) $(TEST_EXE)
