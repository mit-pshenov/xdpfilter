/*
 * canonical_ruleset.inc — MVP-4.2 §5.42 Canonical rule-set (SOURCE OF TRUTH).
 *
 * The exact 12-rule mixed-primitive Gi set, transcribed verbatim from the
 * §5.42 "Canonical rule-set" table (D-mvp-4.2-CANONICAL). The harness derives
 * the prefix-closed LPM masks, the proto-hash masks, the dst-port range table,
 * the per-axis wildcard masks, and the action table from THIS array. The
 * tester's bitvec_oracle.py transcribes the SAME table independently (the
 * independence is the ALGORITHM — naive O(N) scan vs closure-based bit-vector
 * — NOT the data). If the two transcriptions diverge, the agreement ctest
 * fails loudly.
 *
 * `id` = bit position = first-match priority (lower id wins).
 * proto: TCP=6, UDP=17, ICMP=1; -1 = wildcard (axis unconstrained).
 * dst-port [lo,hi] inclusive (exact = [p,p]); lo=-1 = wildcard.
 * dst_cidr / src_cidr NULL = wildcard. action: 0=PASS, 1=DROP.
 *
 * Header-fragment: #include'd exactly once by bitvec_harness.cpp. Not a
 * standalone TU.
 */
#ifndef XDPMF_TESTS_BITVEC_CANONICAL_RULESET_INC
#define XDPMF_TESTS_BITVEC_CANONICAL_RULESET_INC

struct bv_rule {
    unsigned    id;
    const char *dst_cidr; /* NULL = wildcard */
    const char *src_cidr; /* NULL = wildcard */
    int         proto;    /* -1 = wildcard, else IP proto number */
    int         port_lo;  /* -1 = wildcard */
    int         port_hi;
    int         action;   /* 0 = PASS, 1 = DROP */
};

static const struct bv_rule kCanonicalRules[] = {
    /* id  dst-IP            src-IP             proto port_lo port_hi action */
    {  0, "10.1.2.0/24",     0,                 6,    1000,   2000,   1 },
    {  1, "10.1.0.0/16",     0,                 6,      -1,     -1,   0 },
    {  2, "10.0.0.0/8",      0,                -1,      -1,     -1,   0 },
    {  3, "192.168.1.0/24",  0,                17,      53,     53,   1 },
    {  4, "192.168.0.0/16", "172.16.0.0/12",   17,      53,     53,   0 },
    {  5,  0,               "10.5.0.0/16",      6,     443,    443,   1 },
    {  6, "203.0.113.0/24",  0,                -1,    8080,   8090,   0 },
    {  7,  0,                0,                 1,      -1,     -1,   0 },
    {  8, "10.1.2.128/25",   0,                 6,    1000,   2000,   0 },
    {  9, "198.51.100.0/24","198.51.100.0/24",  6,      22,     22,   0 },
    { 10, "10.2.0.0/16",     0,                17,    5000,   6000,   1 },
    { 11,  0,                0,                -1,    9999,   9999,   0 },
};

#define BITVEC_CANONICAL_RULE_COUNT \
    (sizeof(kCanonicalRules) / sizeof(kCanonicalRules[0]))

#endif /* XDPMF_TESTS_BITVEC_CANONICAL_RULESET_INC */
