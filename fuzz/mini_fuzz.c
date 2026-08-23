// Minimal coverage-guided mutation fuzzer (libFuzzer-lite) for CLT clang,
// which lacks the libFuzzer runtime. Uses -fsanitize-coverage=trace-pc-guard
// edge counters to decide which inputs enter the corpus, and installs signal
// handlers to dump the crashing input before dying.

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

#define MAX_INPUT_LEN 8192
#define MAX_CORPUS 8192
#define EDGE_BUCKETS (1u << 21)

static uint8_t g_input[MAX_INPUT_LEN];
static size_t g_input_len;
static volatile uint64_t g_edges_seen[EDGE_BUCKETS / 64];
static volatile uint32_t g_epoch;
static volatile uint32_t g_new_edges;

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop)
{
    for (uint32_t* p = start; p < stop; ++p) {
        *p = (uint32_t)((uintptr_t)p % EDGE_BUCKETS);
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t* guard)
{
    const uint32_t idx = *guard;
    const uint64_t word = (uint64_t)1 << (idx & 63);
    const uint32_t bucket = idx >> 6;
    if ((g_edges_seen[bucket] & word) == 0) {
        g_edges_seen[bucket] |= word;
        ++g_new_edges;
    }
    (void)g_epoch;
}

typedef struct {
    size_t len;
    uint8_t data[MAX_INPUT_LEN];
} corpus_entry_t;

static corpus_entry_t g_corpus[MAX_CORPUS];
static size_t g_corpus_len = 0;

static uint64_t g_rand_state = 0x9e3779b97f4a7c15ULL;

static inline uint64_t rand_next(void)
{
    // splitmix64
    g_rand_state += 0x9e3779b97f4a7c15ULL;
    uint64_t z = g_rand_state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static void save_crash(const int sig)
{
    char name[128];
    const long ts = (long)time(NULL);
    snprintf(name, sizeof(name), "artifacts/crash-sig%d-%ld-%zu", sig, ts, g_input_len);
    const int fd = open(name, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        ssize_t ignored = write(fd, g_input, g_input_len);
        (void)ignored;
        close(fd);
    }
    // Best-effort marker for the runner script
    fprintf(stderr, "\n=== CRASH (signal %d), input saved to %s ===\n", sig, name);
}

static void crash_handler(const int sig)
{
    save_crash(sig);
    signal(sig, SIG_DFL);
    raise(sig);
}

static void corpus_add(const uint8_t* const data, const size_t len)
{
    if (g_corpus_len >= MAX_CORPUS) {
        // Evict a random entry (keep index 0..15, the structured seeds)
        const size_t victim = 16 + (size_t)(rand_next() % (MAX_CORPUS - 16));
        if (victim < g_corpus_len) {
            g_corpus[victim] = g_corpus[g_corpus_len - 1];
            --g_corpus_len;
        }
    }
    if (g_corpus_len >= MAX_CORPUS) {
        return;
    }
    corpus_entry_t* const entry = &g_corpus[g_corpus_len++];
    entry->len = len;
    memcpy(entry->data, data, len);
}

static const uint8_t SEEDS[][32] = {
    { 0x00, 0x08, 0x01 }, // target0: protobuf field1 varint
    { 0x00, 0x0a, 0x04, 'a', 'b', 'c', 'd' }, // field1 length-delim
    { 0x00, 0x12, 0x02, 0x08, 0x2a }, // field3 nested message
    { 0x00, 0xff, 0xff, 0xff, 0xff, 0x0f }, // large varint
    { 0x04, 0x00, 0x08, 0x01, 0x12, 0x00 }, // sign_tx-ish: addr_n + coin
    { 0x05, 0x00, 0x0a, 0x00 }, // tx_ack-ish
    { 0x08, 0x00, 0x08, 0x02, 0x12, 0x01, 0x00 }, // multisig-ish
    { 0x09, 0x00, 0x0a, 0x14 }, // eth get_address-ish
    { 0x0b, 0x00, 0x0a, 0x02, 0x08, 0x01 }, // definitions-ish
};

static const uint8_t INTERESTING[] = { 0x00, 0x01, 0x02, 0x08, 0x0a, 0x10, 0x12, 0x1f, 0x20, 0x3f, 0x7f, 0x80, 0xff,
    0xfe, 0x81, 0x40, 0x23, 0x2a, 0x55 };

static void mutate(uint8_t* const buf, size_t* const len)
{
    size_t n = 1 + (size_t)(rand_next() % 8);
    while (n--) {
        const uint64_t op = rand_next() % 100;
        if (*len == 0) {
            buf[(*len)++] = (uint8_t)rand_next();
            continue;
        }
        const size_t pos = (size_t)(rand_next() % *len);
        if (op < 30) {
            // bit flip
            buf[pos] ^= (uint8_t)(1u << (rand_next() & 7));
        } else if (op < 45) {
            // interesting byte
            buf[pos] = INTERESTING[rand_next() % sizeof(INTERESTING)];
        } else if (op < 55) {
            // arithmetic
            buf[pos] = (uint8_t)(buf[pos] + (rand_next() % 32) - 16);
        } else if (op < 70 && *len > 1) {
            // delete slice
            const size_t d = 1 + (size_t)(rand_next() % 8);
            const size_t cl = d < *len - pos ? d : *len - pos;
            memmove(buf + pos, buf + pos + cl, *len - pos - cl);
            *len -= cl;
        } else if (op < 85 && *len < MAX_INPUT_LEN) {
            // insert slice of random/interesting bytes
            const size_t d = 1 + (size_t)(rand_next() % 8);
            size_t cl = d;
            if (pos + cl > MAX_INPUT_LEN) {
                cl = MAX_INPUT_LEN - pos;
            }
            if (*len + cl > MAX_INPUT_LEN) {
                cl = MAX_INPUT_LEN - *len;
            }
            if (cl) {
                memmove(buf + pos + cl, buf + pos, *len - pos);
                for (size_t i = 0; i < cl; ++i) {
                    buf[pos + i] = (rand_next() & 1) ? (uint8_t)rand_next()
                                                     : INTERESTING[rand_next() % sizeof(INTERESTING)];
                }
                *len += cl;
            }
        } else if (g_corpus_len > 1) {
            // splice: copy a chunk from another corpus entry
            const corpus_entry_t* const other = &g_corpus[rand_next() % g_corpus_len];
            if (other->len) {
                const size_t opos = (size_t)(rand_next() % other->len);
                size_t cl = 1 + (size_t)(rand_next() % 16);
                if (opos + cl > other->len) {
                    cl = other->len - opos;
                }
                if (pos + cl <= *len) {
                    memcpy(buf + pos, other->data + opos, cl);
                }
            }
        }
    }
}

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static const char* __asan_default_options(void)
{
    return "abort_on_error=1:detect_leaks=0:handle_abort=1";
}

int main(const int argc, char** argv)
{
    double seconds = 90.0;
    if (argc > 1) {
        seconds = atof(argv[1]);
        if (seconds <= 0) {
            seconds = 90.0;
        }
    }
    mkdir("artifacts", 0755);

    signal(SIGABRT, crash_handler);
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS, crash_handler);
    signal(SIGILL, crash_handler);
    signal(SIGFPE, crash_handler);

    // Seed the corpus
    for (size_t i = 0; i < sizeof(SEEDS) / sizeof(SEEDS[0]); ++i) {
        corpus_add(SEEDS[i], sizeof(SEEDS[i]) / sizeof(SEEDS[0][0]) ? sizeof(SEEDS[i]) : 1);
    }
    for (size_t i = 0; i < 64; ++i) {
        uint8_t buf[64];
        const size_t len = 1 + (size_t)(rand_next() % sizeof(buf));
        for (size_t j = 0; j < len; ++j) {
            buf[j] = (uint8_t)rand_next();
        }
        corpus_add(buf, len);
    }

    const double deadline = now_seconds() + seconds;
    uint64_t execs = 0;
    uint64_t total_edges = 0;
    time_t last_report = time(NULL);
    uint8_t buf[MAX_INPUT_LEN];

    while (now_seconds() < deadline) {
        size_t len;
        if ((rand_next() & 7) == 0 || g_corpus_len == 0) {
            // Fully random input
            len = 1 + (size_t)(rand_next() % 256);
            for (size_t i = 0; i < len; ++i) {
                buf[i] = (uint8_t)rand_next();
            }
        } else {
            const corpus_entry_t* const src = &g_corpus[rand_next() % g_corpus_len];
            len = src->len;
            memcpy(buf, src->data, len);
            mutate(buf, &len);
        }

        g_new_edges = 0;
        memcpy(g_input, buf, len);
        g_input_len = len;

        LLVMFuzzerTestOneInput(g_input, g_input_len);
        ++execs;

        if (g_new_edges > 0) {
            corpus_add(g_input, g_input_len);
        }

        const time_t now = time(NULL);
        if (now != last_report) {
            last_report = now;
            for (size_t i = 0; i < EDGE_BUCKETS / 64; ++i) {
                total_edges += __builtin_popcountll(g_edges_seen[i]);
            }
            fprintf(stderr, "execs=%llu corpus=%zu edges=%llu execs/s=%.0f\n", (unsigned long long)execs,
                g_corpus_len, (unsigned long long)total_edges, execs / (seconds - (deadline - now_seconds())));
            total_edges = 0;
        }
    }

    fprintf(stderr, "\nDone: %llu execs, corpus=%zu, no crash\n", (unsigned long long)execs, g_corpus_len);
    return 0;
}
