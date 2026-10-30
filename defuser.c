#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    uint32_t high = (uint32_t)(challenge >> 32);
    uint32_t low = (uint32_t)challenge;
    uint32_t middle = (uint32_t)(challenge >> 16);

    /* p1_compute calls step2(high, low), step0(low, middle), then
       step1(step0_result, step2_result). All operations wrap at 32 bits. */
    uint32_t step2_result = (5u * high) ^ (low + 0x63e9u);
    uint32_t step0_result = (3u * low + middle) ^ 0x8cc1u;
    values[0] = (step2_result + 0x8830u) ^ step0_result;
    return write_answer(out, cap, values, count);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 6;
    values[0] = 3u * (uint32_t)((challenge >> 6) & 0xffu);
    for (uint32_t i = 1; i < count; ++i) {
        uint32_t from_challenge = (uint32_t)((challenge >> (2u * i + 5u)) & 0x3fu) + 1u;
        uint32_t from_previous = 3u * values[i - 1] - i;
        values[i] = from_challenge ^ from_previous;
    }
    return write_answer(out, cap, values, count);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 2;
    uint32_t index = (uint32_t)challenge & 7u;
    uint32_t v = (uint32_t)(challenge >> 32) ^ (uint32_t)(challenge >> 3);
    values[0] = index;

    /* Jump-table order is case_6, case_5, case_3, case_1,
       case_0, case_4, case_7, case_2; it differs from symbol numbering. */
    switch (index) {
    case 0: values[1] = (v ^ 0xbfd0u) + (v >> 2); break;
    case 1: values[1] = 5u * v + 0x1da79u; break;
    case 2: values[1] = (v ^ 0x1cb5u) + (v >> 1); break;
    case 3: values[1] = 5u * v + 0xdc6eu; break;
    case 4: values[1] = 3u * v + 0xcf30u; break;
    case 5: values[1] = (2u * v) ^ 0x51e1u; break;
    case 6: values[1] = 3u * v + 0xb83bu; break;
    case 7: values[1] = (4u * v) ^ 0x4ac5u; break;
    }
    return write_answer(out, cap, values, count);
}

static uint32_t phase4_walk(uint32_t target, uint32_t low, uint32_t high, uint32_t salt) {
    uint32_t middle = low + ((high - low) >> 1);
    if (target == middle) return (middle + 0x19u) ^ salt;
    uint32_t child;
    if (target < middle) {
        child = phase4_walk(target, low, middle - 1u, salt);
        return (3u * child) ^ (middle + salt) ^ 0x0eu;
    }
    child = phase4_walk(target, middle + 1u, high, salt);
    return (3u * child) ^ (middle + salt) ^ 0x13u;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    uint32_t target = (uint32_t)challenge & 0x7fu;
    uint32_t salt = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32);
    values[0] = phase4_walk(target, 0, 127, salt);
    return write_answer(out, cap, values, count);
}

struct phase5_node {
    const struct phase5_node *next;
    uint32_t tag;
    uint32_t bias;
};

/* Fixed node data read from this bomb's p5_nodes (16 bytes per node).
   Links below preserve its pointer graph; these are not per-seed answers. */
static const struct phase5_node phase5_nodes[12] = {
    {&phase5_nodes[8],  0x0a1cu, 0x585au},
    {&phase5_nodes[10], 0x0721u, 0x986fu},
    {&phase5_nodes[11], 0x0040u, 0xc40cu},
    {&phase5_nodes[0],  0x0118u, 0x06abu},
    {NULL,            0x0317u, 0xc3b8u},
    {&phase5_nodes[7],  0x060au, 0xb764u},
    {&phase5_nodes[9],  0x0b46u, 0x3c39u},
    {&phase5_nodes[1],  0x0205u, 0x2a12u},
    {&phase5_nodes[6],  0x0478u, 0x8d15u},
    {&phase5_nodes[2],  0x082cu, 0xafe2u},
    {&phase5_nodes[3],  0x0555u, 0xd961u},
    {&phase5_nodes[4],  0x0959u, 0xc65au},
};

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 2;
    static const unsigned heads[8] = {5, 7, 1, 10, 3, 0, 8, 6};
    const struct phase5_node *node = &phase5_nodes[heads[challenge & 7u]];
    uint32_t hops = (uint32_t)(challenge >> 3) & 3u;
    uint32_t accumulator = (uint32_t)(challenge >> 6)
                         ^ (uint32_t)(challenge >> 32) ^ 0x2c04u;
    for (uint32_t step = 0; step <= hops; ++step) {
        accumulator = (3u * accumulator + node->bias) ^ node->tag;
        values[1] = node->tag;
        if (step < hops) node = node->next;
    }
    values[0] = accumulator;
    return write_answer(out, cap, values, count);
}

static uint32_t phase6_op0(uint32_t v) { return (v >> 1) | (v << 31); }
static uint32_t phase6_op1(uint32_t v) { return (v ^ 0xd0b4u) + 2u * v; }
static uint32_t phase6_op2(uint32_t v) { return (v + 0x1f88u) ^ (v >> 1); }
static uint32_t phase6_op3(uint32_t v) { return ((v >> 5) ^ v) + 0x59f9u; }
static uint32_t phase6_op4(uint32_t v) { return ((v << 5) | (v >> 27)) ^ 0x19dfu; }
static uint32_t phase6_op5(uint32_t v) { return (8u * v + 0xa3bfu) ^ (7u * v); }

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 1;
    /* Preserve the actual p6_ops table, including repeated function pointers. */
    static uint32_t (*const operations[8])(uint32_t) = {
        phase6_op4, phase6_op5, phase6_op5, phase6_op0,
        phase6_op2, phase6_op0, phase6_op1, phase6_op3
    };
    uint32_t v = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);
    v = operations[challenge & 7u](v) ^ 0x3f3au;
    values[0] = operations[(challenge >> 3) & 7u](v) + 0x3a95u;
    return write_answer(out, cap, values, count);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t mode = (uint32_t)context & 3u;
    uint32_t folded_challenge = (uint32_t)challenge ^ (uint32_t)(challenge >> 32);
    uint32_t folded_context = (uint32_t)context ^ (uint32_t)(context >> 32);
    uint32_t mixed = folded_challenge ^ folded_context;
    mixed = ((mixed >> 5) | (mixed << 27)) ^ 0x4bbdu;
    uint32_t second = mixed ^ (mode * 0x9e88u) ^ (uint32_t)(context >> 16);
    uint32_t third = second ^ (folded_context + mode + 0xd535u + (folded_challenge >> 5));

    /* secret_copy writes from offset 0; the gate flag is at offset 32
       and secret_phase parses the suffix at offset 36. 0x4e45504f is
       the little-endian byte sequence OPEN. No return address is touched. */
    int size = snprintf(out, cap, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPEN%" PRIu32
                        " %" PRIu32 " %" PRIu32, mode, second, third);
    return size < 0 || (size_t)size >= cap;
}
