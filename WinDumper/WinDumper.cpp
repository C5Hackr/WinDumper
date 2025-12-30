#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <dbghelp.h>
#include <winhttp.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <psapi.h>
#include <ctype.h>

#include "capstone/capstone/capstone.h"

#if defined(_M_X64)
#pragma comment(lib, "capstone_x64\\capstone_x64.lib")
#elif defined(_M_IX86)
#pragma comment(lib, "capstone_x86\\capstone_x86.lib")
#elif defined(_M_ARM64)
#pragma comment(lib, "capstone_arm64\\capstone_arm64.lib")
#endif

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "winhttp.lib")

typedef struct Record {
    char* name;
    DWORD64 addr;
    DWORD size;
    DWORD tag;
    DWORD flags;
} Record;

static Record* g_records = NULL;
static size_t  g_count = 0;
static size_t  g_cap = 0;

static void add_or_update_record(const char* name, DWORD64 addr, DWORD size, DWORD tag, DWORD flags)
{
    for (size_t i = 0; i < g_count; ++i) {
        if (strcmp(g_records[i].name, name) == 0) {
            if (size > g_records[i].size || (size == g_records[i].size && addr < g_records[i].addr)) {
                g_records[i].addr = addr;
                g_records[i].size = size;
                g_records[i].tag = tag;
                g_records[i].flags = flags;
            }
            return;
        }
    }

    if (g_count == g_cap) {
        size_t new_cap = g_cap ? (g_cap * 2) : 2048;
        Record* tmp = (Record*)realloc(g_records, new_cap * sizeof(*g_records));
        if (!tmp) return;
        g_records = tmp;
        g_cap = new_cap;
    }

    size_t nlen = strlen(name);
    g_records[g_count].name = (char*)malloc(nlen + 1);
    if (!g_records[g_count].name) return;

    memcpy(g_records[g_count].name, name, nlen + 1);
    g_records[g_count].addr = addr;
    g_records[g_count].size = size;
    g_records[g_count].tag = tag;
    g_records[g_count].flags = flags;
    ++g_count;
}

static size_t g_aob_max_bytes_override = 0;

typedef struct Pattern
{
    BYTE* bytes;
    BYTE* is_wild;
    SIZE_T length;
} Pattern;

int hexval(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    c = (char)tolower((unsigned char)c);
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    return -1;
}

int parse_pattern(const char* pattern_str, Pattern* out)
{
    memset(out, 0, sizeof(*out));

    SIZE_T n = strlen(pattern_str);
    BYTE* bytes = (BYTE*)malloc(n);
    BYTE* wild = (BYTE*)malloc(n);
    if (!bytes || !wild) {
        free(bytes);
        free(wild);
        return 0;
    }

    SIZE_T count = 0;
    const char* p = pattern_str;

    while (*p)
    {
        while (*p && isspace((unsigned char)*p)) {
            p++;
        }

        if (!*p) {
            break;
        }

        if (*p == '?')
        {
            p++;
            if (*p == '?') {
                p++;
            }
            bytes[count] = 0;
            wild[count] = 1;
            count++;
            continue;
        }

        int hi = hexval(*p++);
        while (*p && isspace((unsigned char)*p)) {
            p++;
        }
        int lo = hexval(*p++);

        if (hi < 0 || lo < 0)
        {
            free(bytes);
            free(wild);
            return 0;
        }

        bytes[count] = (BYTE)((hi << 4) | lo);
        wild[count] = 0;
        count++;
    }

    out->bytes = (BYTE*)realloc(bytes, count ? count : 1);
    out->is_wild = (BYTE*)realloc(wild, count ? count : 1);
    out->length = count;
    return (count > 0);
}

void free_pattern(Pattern* pat)
{
    free(pat->bytes);
    free(pat->is_wild);
    memset(pat, 0, sizeof(*pat));
}

int MemoryComparePattern(const BYTE* data, const Pattern* pat)
{
    for (SIZE_T i = 0; i < pat->length; i++)
    {
        if (pat->is_wild[i]) {
            continue;
        }

        if (data[i] != pat->bytes[i]) {
            return 0;
        }
    }
    return 1;
}

uintptr_t FindSignaturePattern(uintptr_t start, SIZE_T size, const Pattern* pat)
{
    BYTE* data = (BYTE*)malloc(size);
    SIZE_T bytesRead = 0;

    if (!data) {
        return 0;
    }

    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)start, data, size, &bytesRead) || bytesRead != size)
    {
        free(data);
        return 0;
    }

    if (pat->length == 0 || pat->length > size)
    {
        free(data);
        return 0;
    }

    for (SIZE_T i = 0; i <= size - pat->length; i++)
    {
        if (MemoryComparePattern(data + i, pat))
        {
            free(data);
            return start + i;
        }
    }

    free(data);
    return 0;
}

uintptr_t ScanPatternText(const char* moduleName, const char* patternText)
{
    HMODULE hModule = NULL;

    if (!moduleName || moduleName[0] == '\0') {
        hModule = GetModuleHandleA(NULL);
    }
    else {
        hModule = GetModuleHandleA(moduleName);
    }

    if (!hModule) {
        return 0;
    }

    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return 0;
    }

    Pattern pat;
    if (!parse_pattern(patternText, &pat)) {
        return 0;
    }

    uintptr_t baseAddress = (uintptr_t)modInfo.lpBaseOfDll;
    SIZE_T moduleSize = (SIZE_T)modInfo.SizeOfImage;

    uintptr_t result = FindSignaturePattern(baseAddress, moduleSize, &pat);
    free_pattern(&pat);
    return result;
}

typedef struct {
    int wildcard_all_disp;
    int wildcard_ptr_imm;
    int wildcard_rip_disp;
    int wildcard_branch_imm;
    int wc_arm64_branch;
    int wc_arm64_adr;
    int wc_arm64_literal;
    int instr_target;
} SigProfile;

#if defined(_M_ARM64)
static const SigProfile g_profiles[5] = {
    {0,0,0,0, 1,1,1, 20},
    {0,0,0,0, 1,1,1, 28},
    {0,0,0,0, 1,1,1, 40},
    {0,0,0,0, 1,1,0, 40},
    {0,0,0,0, 1,0,0, 48},
};
#else
static const SigProfile g_profiles[5] = {
    {1,1,1,1, 0,0,0, 18},
    {1,1,1,1, 0,0,0, 26},
    {1,0,1,1, 0,0,0, 26},
    {0,0,1,1, 0,0,0, 26},
    {0,0,1,1, 0,0,0, 40},
};
#endif

typedef enum AOB_PORTABILITY_MODE {
    AOB_PORT_FORCE_SUPER_PORTABLE = 0,
    AOB_PORT_FORCE_PORTABLE = 1,
    AOB_PORT_PORTABLE_PREFERRED = 2,
    AOB_PORT_RELIABILITY_FIRST = 3
} AOB_PORTABILITY_MODE;

typedef struct {
    char* name;
    SIZE_T count;
    SIZE_T cap;
    char** aobs;
} AOBEntryDyn;

static AOBEntryDyn* g_merge = NULL;
static SIZE_T g_merge_count = 0;
static SIZE_T g_merge_cap = 0;

static int ensure_merge_cap(SIZE_T need)
{
    if (g_merge_cap >= need) return 1;
    SIZE_T nc = g_merge_cap ? g_merge_cap * 2 : 1024;
    while (nc < need) nc *= 2;
    AOBEntryDyn* p = (AOBEntryDyn*)realloc(g_merge, nc * sizeof(*g_merge));
    if (!p) return 0;
    g_merge = p;
    g_merge_cap = nc;
    return 1;
}

static int ensure_entry_aob_cap(AOBEntryDyn* e, SIZE_T need)
{
    if (e->cap >= need) return 1;
    SIZE_T nc = e->cap ? e->cap * 2 : 4;
    while (nc < need) nc *= 2;
    char** p = (char**)realloc(e->aobs, nc * sizeof(*e->aobs));
    if (!p) return 0;
    e->aobs = p;
    e->cap = nc;
    return 1;
}

static AOBEntryDyn* find_merge_entry(const char* name)
{
    for (SIZE_T i = 0; i < g_merge_count; ++i) {
        if (strcmp(g_merge[i].name, name) == 0)
            return &g_merge[i];
    }
    return NULL;
}

static int entry_has_aob(const AOBEntryDyn* e, const char* aob)
{
    for (SIZE_T i = 0; i < e->count; ++i) {
        if (strcmp(e->aobs[i], aob) == 0)
            return 1;
    }
    return 0;
}

static void merge_add_aob_owned(const char* name, char* aob_owned)
{
    if (!name || !aob_owned) return;

    AOBEntryDyn* e = find_merge_entry(name);
    if (!e) {
        if (!ensure_merge_cap(g_merge_count + 1)) { free(aob_owned); return; }
        e = &g_merge[g_merge_count++];
        memset(e, 0, sizeof(*e));
        e->name = _strdup(name);
        if (!e->name) { g_merge_count--; free(aob_owned); return; }
    }

    if (entry_has_aob(e, aob_owned)) {
        free(aob_owned);
        return;
    }

    if (!ensure_entry_aob_cap(e, e->count + 1)) { free(aob_owned); return; }
    e->aobs[e->count++] = aob_owned;
}

static void print_merged_aob_table_flat_to_file(const char* outPath)
{
    FILE* f = NULL;
    if (fopen_s(&f, outPath, "wb") != 0 || !f) {
        printf("[ERROR] Failed to open output file: %s\n", outPath);
        return;
    }

    SIZE_T maxSeen = 0;
    for (SIZE_T i = 0; i < g_merge_count; ++i)
        if (g_merge[i].count > maxSeen) maxSeen = g_merge[i].count;
    if (maxSeen == 0) maxSeen = 1;

    fprintf(f, "// ===== GENERATED AOB TABLE =====\n\n");
    fprintf(f, "#include <stddef.h>\n\n");
    fprintf(f, "#define MAX_AOBS_PER_FUNC %llu\n\n", (unsigned long long)maxSeen);

    fprintf(f, "typedef struct {\n");
    fprintf(f, "    const char* name;\n");
    fprintf(f, "    size_t count;\n");
    fprintf(f, "    const char* aob[MAX_AOBS_PER_FUNC];\n");
    fprintf(f, "} AOBEntry;\n\n");

    fprintf(f, "static const AOBEntry aob_table[] = {\n");

    for (SIZE_T i = 0; i < g_merge_count; ++i) {
        fprintf(f, " { \"%s\", %llu, { ",
            g_merge[i].name,
            (unsigned long long)g_merge[i].count);

        SIZE_T j = 0;
        for (; j < g_merge[i].count; ++j) {
            fprintf(f, "\"%s\"", g_merge[i].aobs[j]);
            if (j + 1 < maxSeen) fprintf(f, ", ");
        }

        for (; j < maxSeen; ++j) {
            fprintf(f, "NULL");
            if (j + 1 < maxSeen) fprintf(f, ", ");
        }

        fprintf(f, " } },\n");
    }

    fprintf(f, " { NULL, 0, { NULL } }\n");
    fprintf(f, "};\n");

    fclose(f);

    printf("[OK] Wrote AOB table to: %s\n", outPath);
}

static void free_merged_aob_table(void)
{
    for (SIZE_T i = 0; i < g_merge_count; ++i) {
        for (SIZE_T j = 0; j < g_merge[i].count; ++j) {
            free(g_merge[i].aobs[j]);
        }
        free(g_merge[i].aobs);
        free(g_merge[i].name);
    }
    free(g_merge);
    g_merge = NULL;
    g_merge_count = 0;
    g_merge_cap = 0;
}

static void rstrip_spaces(char* s)
{
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) {
        s[--n] = '\0';
    }
}

static void append_token(char* out, size_t cap, const char* tok) {
    size_t len = strlen(out);
    size_t tlen = strlen(tok);
    if (len + tlen + 1 >= cap) return;
    memcpy(out + len, tok, tlen);
    out[len + tlen] = '\0';
}

static void append_byte_or_wc(char* out, size_t cap, int wc, uint8_t b) {
    if (wc) {
        append_token(out, cap, "?? ");
    }
    else {
        char tmp[4];
        static const char hex[] = "0123456789ABCDEF";
        tmp[0] = hex[(b >> 4) & 0xF];
        tmp[1] = hex[b & 0xF];
        tmp[2] = ' ';
        tmp[3] = '\0';
        append_token(out, cap, tmp);
    }
}

static int insn_in_group(const cs_insn* insn, uint8_t grp) {
    for (uint8_t i = 0; i < insn->detail->groups_count; i++)
        if (insn->detail->groups[i] == grp) return 1;
    return 0;
}

static int build_aob_x86x64_profile(
    const uint8_t* code, size_t code_max,
    const SigProfile* prof,
    char* out, size_t out_cap)
{
    size_t bytes_emitted = 0;
    size_t byte_cap = (g_aob_max_bytes_override != 0) ? g_aob_max_bytes_override : (size_t)-1;

    out[0] = '\0';

    csh h;
#if defined(_M_X64)
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return 0;
#elif defined(_M_IX86)
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &h) != CS_ERR_OK) return 0;
#else
    return 0;
#endif
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = cs_malloc(h);
    if (!insn) { cs_close(&h); return 0; }

    const uint8_t* p = code;
    size_t left = code_max;
    uint64_t addr = (uint64_t)(uintptr_t)code;

    int instr_emitted = 0;
    int any = 0;

    while (left > 0 && instr_emitted < prof->instr_target) {
        const uint8_t* cur = p;
        size_t cur_left = left;
        uint64_t cur_addr = addr;

        if (!cs_disasm_iter(h, &cur, &cur_left, &cur_addr, insn)) {
            append_byte_or_wc(out, out_cap, 0, *p);
            p++; left--; addr++;
            any = 1;
            continue;
        }

        any = 1;
        instr_emitted++;

        const cs_x86* x = &insn->detail->x86;

        uint8_t wc[32] = { 0 };
        size_t ilen = insn->size;
        if (ilen > sizeof(wc)) ilen = sizeof(wc);

        int is_branch = insn_in_group(insn, CS_GRP_JUMP) || insn_in_group(insn, CS_GRP_CALL);

        uint8_t imm_off = x->encoding.imm_offset;
        uint8_t imm_size = x->encoding.imm_size;
        uint8_t disp_off = x->encoding.disp_offset;
        uint8_t disp_size = x->encoding.disp_size;

#if defined(_M_X64)
        int has_riprel = 0;
        for (uint8_t i = 0; i < x->op_count; i++) {
            if (x->operands[i].type == X86_OP_MEM && x->operands[i].mem.base == X86_REG_RIP) {
                has_riprel = 1;
                break;
            }
        }
#else
        int has_riprel = 0;
#endif

        if (prof->wildcard_branch_imm && is_branch && imm_size && imm_off + imm_size <= ilen) {
            for (uint8_t i = 0; i < imm_size; i++) wc[imm_off + i] = 1;
        }

#if defined(_M_X64)
        if (prof->wildcard_rip_disp && has_riprel && disp_size && disp_off + disp_size <= ilen) {
            for (uint8_t i = 0; i < disp_size; i++) wc[disp_off + i] = 1;
        }
#endif

        if (prof->wildcard_all_disp && disp_size && disp_off + disp_size <= ilen) {
            for (uint8_t i = 0; i < disp_size; i++) wc[disp_off + i] = 1;
        }

#if defined(_M_X64)
        if (prof->wildcard_ptr_imm && imm_size && imm_off + imm_size <= ilen) {
            uint64_t immv = 0;
            for (uint8_t i = 0; i < imm_size && i < 8; i++)
                immv |= ((uint64_t)insn->bytes[imm_off + i]) << (8u * i);

            if (immv >= 0x00007FF000000000ULL && immv <= 0x00007FFFFFFFFFFFULL) {
                for (uint8_t i = 0; i < imm_size; i++) wc[imm_off + i] = 1;
            }
        }
#endif

        for (size_t i = 0; i < ilen; i++) {
            if (bytes_emitted >= byte_cap) goto done;
            append_byte_or_wc(out, out_cap, wc[i], insn->bytes[i]);
            bytes_emitted++;
        }

        left -= insn->size;
        p += insn->size;
        addr += insn->size;
    }

done:
    cs_free(insn, 1);
    cs_close(&h);
    return any;
}

static int is_arm64_branchish(unsigned int id) {
    switch (id) {
    case AARCH64_INS_B:
    case AARCH64_INS_BL:
    case AARCH64_INS_BR:
    case AARCH64_INS_BLR:
    case AARCH64_INS_RET:
    case AARCH64_INS_CBZ:
    case AARCH64_INS_CBNZ:
    case AARCH64_INS_TBZ:
    case AARCH64_INS_TBNZ:
        return 1;
    default:
        return 0;
    }
}

static int is_arm64_pcrel(unsigned int id) {
    switch (id) {
    case AARCH64_INS_ADR:
    case AARCH64_INS_ADRP:
    case AARCH64_INS_LDR:
    case AARCH64_INS_LDRSW:
    case AARCH64_INS_PRFM:
        return 1;
    default:
        return 0;
    }
}

static int arm64_has_imm_operand(const cs_aarch64* a) {
    for (uint8_t i = 0; i < a->op_count; i++)
        if (a->operands[i].type == AARCH64_OP_IMM) return 1;
    return 0;
}

static int arm64_has_mem_literal(const cs_aarch64* a) {
    for (uint8_t i = 0; i < a->op_count; i++) {
        if (a->operands[i].type == AARCH64_OP_MEM) {
            if (a->operands[i].mem.base == AARCH64_REG_INVALID) {
                return 1;
            }
        }
    }
    return 0;
}

static int build_aob_arm64_profile(
    const uint8_t* code, size_t code_max,
    const SigProfile* prof,
    char* out, size_t out_cap)
{
    size_t bytes_emitted = 0;
    size_t byte_cap = (g_aob_max_bytes_override != 0) ? g_aob_max_bytes_override : (size_t)-1;

    out[0] = '\0';

    csh h;
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &h) != CS_ERR_OK) return 0;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = cs_malloc(h);
    if (!insn) { cs_close(&h); return 0; }

    const uint8_t* p = code;
    size_t left = code_max;
    uint64_t addr = (uint64_t)(uintptr_t)code;

    int instr_emitted = 0;
    int any = 0;

    while (left >= 4 && instr_emitted < prof->instr_target) {
        const uint8_t* cur = p;
        size_t cur_left = left;
        uint64_t cur_addr = addr;

        if (!cs_disasm_iter(h, &cur, &cur_left, &cur_addr, insn)) {
            for (int i = 0; i < 4 && left > 0; i++) {
                append_byte_or_wc(out, out_cap, 0, *p);
                p++; left--; addr++;
            }
            any = 1;
            continue;
        }

        any = 1;
        instr_emitted++;

        const cs_aarch64* a = &insn->detail->aarch64;

        int wc_whole = 0;

        if (prof->wc_arm64_branch && is_arm64_branchish(insn->id) && arm64_has_imm_operand(a)) {
            wc_whole = 1;
        }

        if (!wc_whole && prof->wc_arm64_adr &&
            (insn->id == AARCH64_INS_ADR || insn->id == AARCH64_INS_ADRP) &&
            arm64_has_imm_operand(a)) {
            wc_whole = 1;
        }

        if (!wc_whole && prof->wc_arm64_literal &&
            (insn->id == AARCH64_INS_LDR || insn->id == AARCH64_INS_LDRSW || insn->id == AARCH64_INS_PRFM) &&
            arm64_has_mem_literal(a)) {
            wc_whole = 1;
        }

        for (size_t i = 0; i < 4; i++) {
            if (bytes_emitted >= byte_cap) goto done;
            append_byte_or_wc(out, out_cap, wc_whole, insn->bytes[i]);
            bytes_emitted++;
        }

        left -= insn->size;
        p += insn->size;
        addr += insn->size;
    }

done:
    cs_free(insn, 1);
    cs_close(&h);
    return any;
}

static char* generate_aob_string(const Record* rec, const char* targetModuleName,
    AOB_PORTABILITY_MODE mode, SIZE_T maxBytesOverride)
{
    const uint8_t* code = (const uint8_t*)(uintptr_t)rec->addr;
    const size_t code_max = 1024;

    int start = 0, end = 4, step = 1;
    switch (mode) {
    case AOB_PORT_FORCE_SUPER_PORTABLE: start = 0; end = 0; step = 1; break;
    case AOB_PORT_PORTABLE_PREFERRED:   start = 0; end = 4; step = 1; break;
    case AOB_PORT_RELIABILITY_FIRST:    start = 4; end = 0; step = -1; break;
    default:                            start = 0; end = 4; step = 1; break;
    }

    for (int idx = start; ; idx += step) {
        const SigProfile* prof = &g_profiles[idx];

        size_t cap = (size_t)prof->instr_target * 32 * 3 + 1;
        char* aob = (char*)malloc(cap);
        if (!aob) return NULL;

        g_aob_max_bytes_override = maxBytesOverride;

        int ok = 0;
#if defined(_M_ARM64)
        ok = build_aob_arm64_profile(code, code_max, prof, aob, cap);
#else
        ok = build_aob_x86x64_profile(code, code_max, prof, aob, cap);
#endif
        if (!ok) {
            free(aob);
            if (idx == end) {
                break;
            }
            continue;
        }

        rstrip_spaces(aob);

        void* found = (void*)ScanPatternText(targetModuleName, aob);
        if ((uintptr_t)found == (uintptr_t)rec->addr) {
            return aob;
        }

        free(aob);

    next:
        if (idx == end) break;
    }

    return NULL;
}

static void dump_and_merge_records(const char* targetModuleName,
    BOOL excludeNullAobs,
    AOB_PORTABILITY_MODE mode,
    SIZE_T maxBytesOverride)
{
    for (size_t i = 0; i < g_count; ++i) {
        char* aob = generate_aob_string(&g_records[i], targetModuleName, mode, maxBytesOverride);

        if (aob) {
            merge_add_aob_owned(g_records[i].name, aob);
        }
        else {
            if (!excludeNullAobs) {
                merge_add_aob_owned(g_records[i].name, _strdup("NULL"));
            }
        }
    }

    for (size_t i = 0; i < g_count; ++i) free(g_records[i].name);
    free(g_records);
    g_records = NULL;
    g_count = 0;
    g_cap = 0;
}

static int is_clean_name_letters_first(const char* s)
{
    if (!s || !s[0]) return 0;

    unsigned char c0 = (unsigned char)s[0];
    if (!isalpha(c0)) return 0;

    for (const unsigned char* p = (const unsigned char*)s + 1; *p; ++p) {
        if (!isalnum(*p)) return 0;
    }
    return 1;
}

static int is_compiler_helper_name(const char* name)
{
    return (name &&
        (strstr(name, "$filt$") ||
            strstr(name, "$fin$") ||
            strstr(name, "$catch$")));
}

#pragma pack(push, 1)
typedef struct CV_INFO_PDB70 {
    DWORD CvSignature;
    GUID Signature;
    DWORD Age;
    char PdbFileName[1];
} CV_INFO_PDB70;
#pragma pack(pop)

static int get_rsds_from_image(HMODULE hMod, GUID* outGuid, DWORD* outAge, char* outPdbName, size_t outPdbNameCap)
{
    if (!hMod || !outGuid || !outAge) return 0;

    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (dd.VirtualAddress == 0 || dd.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) return 0;

    IMAGE_DEBUG_DIRECTORY* dbg = (IMAGE_DEBUG_DIRECTORY*)(base + dd.VirtualAddress);
    size_t count = dd.Size / sizeof(IMAGE_DEBUG_DIRECTORY);

    for (size_t i = 0; i < count; ++i) {
        if (dbg[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW) continue;

        DWORD rva = dbg[i].AddressOfRawData;
        if (!rva) continue;

        CV_INFO_PDB70* cv = (CV_INFO_PDB70*)(base + rva);
        if (cv->CvSignature != 0x53445352) continue;

        *outGuid = cv->Signature;
        *outAge = cv->Age;

        if (outPdbName && outPdbNameCap) {
            strncpy(outPdbName, cv->PdbFileName, outPdbNameCap - 1);
            outPdbName[outPdbNameCap - 1] = '\0';
        }
        return 1;
    }

    return 0;
}

static void guid_to_key_no_dashes_plus_age(const GUID* g, DWORD age, char outKey[64])
{
    sprintf(outKey,
        "%08lX%04hX%04hX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX%lu",
        (unsigned long)g->Data1,
        (unsigned short)g->Data2,
        (unsigned short)g->Data3,
        g->Data4[0], g->Data4[1], g->Data4[2], g->Data4[3],
        g->Data4[4], g->Data4[5], g->Data4[6], g->Data4[7],
        (unsigned long)age
    );
}

static int download_url_to_file_https(const wchar_t* host, const wchar_t* path, const wchar_t* outFile)
{
    int ok = 0;

    HINTERNET hSession = WinHttpOpen(L"pdb-fetch/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!hSession) return 0;

    HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect)
    {
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }

    HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", path,
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);

    if (!hReq)
    {
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }

    WinHttpSetTimeouts(hReq, 5000, 5000, 5000, 15000);

    if (!WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hReq);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }

    if (!WinHttpReceiveResponse(hReq, NULL)) {
        WinHttpCloseHandle(hReq);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }

    DWORD status = 0, statusSize = sizeof(status);
    if (!WinHttpQueryHeaders(hReq,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status, &statusSize, WINHTTP_NO_HEADER_INDEX)) {
        WinHttpCloseHandle(hReq);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }

    if (status != 200) {
        wprintf(L"HTTP %lu for %ls%ls\n", status, host, path);
        WinHttpCloseHandle(hReq);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }

    HANDLE hFile = CreateFileW(outFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        WinHttpCloseHandle(hReq);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
    }

    BYTE buffer[1 << 15];
    DWORD bytesAvail = 0;

    while (WinHttpQueryDataAvailable(hReq, &bytesAvail) && bytesAvail > 0) {
        while (bytesAvail > 0) {
            DWORD toRead = (bytesAvail < sizeof(buffer)) ? bytesAvail : (DWORD)sizeof(buffer);
            DWORD bytesRead = 0;

            if (!WinHttpReadData(hReq, buffer, toRead, &bytesRead) || bytesRead == 0) {
                CloseHandle(hFile);
                WinHttpCloseHandle(hReq);
                if (hConnect) WinHttpCloseHandle(hConnect);
                if (hSession) WinHttpCloseHandle(hSession);
            }

            DWORD written = 0;
            if (!WriteFile(hFile, buffer, bytesRead, &written, NULL) || written != bytesRead) {
                CloseHandle(hFile);
                WinHttpCloseHandle(hReq);
                if (hConnect) WinHttpCloseHandle(hConnect);
                if (hSession) WinHttpCloseHandle(hSession);
            }

            bytesAvail -= bytesRead;
        }
    }

    CloseHandle(hFile);
    WinHttpCloseHandle(hReq);
    ok = 1;

    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);
    return ok;
}

typedef struct EnumContext {
    HMODULE moduleForGetProc;
    uintptr_t textStart;
    uintptr_t textEnd;
} EnumContext;

static int init_text_range(EnumContext* ctx)
{
    BYTE* base = (BYTE*)ctx->moduleForGetProc;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    WORD nsec = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < nsec; i++) {
        char name[9] = { 0 };
        memcpy(name, sec[i].Name, 8);

        if (strcmp(name, ".text") == 0) {
            DWORD rva = sec[i].VirtualAddress;
            DWORD vlen = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;

            ctx->textStart = (uintptr_t)ctx->moduleForGetProc + rva;
            ctx->textEnd = ctx->textStart + vlen;
            return 1;
        }
    }
    return 0;
}

static BOOL CALLBACK enum_symbols_cb(PSYMBOL_INFO s, ULONG symbol_size, PVOID user)
{
    (void)symbol_size;
    EnumContext* ctx = (EnumContext*)user;
    if (!s || !s->NameLen || !s->Name || !s->Name[0]) return TRUE;

    uintptr_t a = (uintptr_t)s->Address;
    if (a < ctx->textStart || a >= ctx->textEnd) return TRUE;

    if (is_compiler_helper_name(s->Name)) return TRUE;
    if (!is_clean_name_letters_first(s->Name)) return TRUE;

    if (GetProcAddress(ctx->moduleForGetProc, s->Name) == NULL) {
        add_or_update_record(s->Name, s->Address, s->Size, s->Tag, s->Flags);
    }
    return TRUE;
}

static int init_dbghelp(HANDLE process, const char* symPath)
{
    DWORD opt = SymGetOptions();
    opt |= SYMOPT_UNDNAME | SYMOPT_FAIL_CRITICAL_ERRORS;
    opt &= ~SYMOPT_DEFERRED_LOADS;
    SymSetOptions(opt);

    if (!SymInitialize(process, symPath, FALSE)) {
        printf("SymInitialize failed: %lu\n", GetLastError());
        return 0;
    }
    return 1;
}

typedef struct {
    HANDLE process;
} Runner;

static void process_one_bin(const char* dllFile, void* user)
{
    Runner* r = (Runner*)user;
    const wchar_t* pdbOut = L".\\ntdll.pdb";

    HANDLE process = GetCurrentProcess();

    if (!init_dbghelp(process, ".")) {
        printf("init_dbghelp failed\n");
        system("pause");
        exit(0);
    }

    HMODULE hMod = LoadLibraryExA(dllFile, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod) {
        printf("[BIN] LoadLibraryExA(%s) failed: %lu\n", dllFile, GetLastError());
        return;
    }

    GUID guid;
    DWORD age = 0;
    char pdbName[260] = { 0 };

    if (!get_rsds_from_image(hMod, &guid, &age, pdbName, sizeof(pdbName))) {
        printf("[BIN] RSDS not found: %s\n", dllFile);
        FreeLibrary(hMod);
        return;
    }

    char key[64] = { 0 };
    guid_to_key_no_dashes_plus_age(&guid, age, key);

    const char* pdbFile = (pdbName[0] ? pdbName : "ntdll.pdb");

    wchar_t path[512];
    wchar_t pdbFileW[260];
    MultiByteToWideChar(CP_UTF8, 0, pdbFile, -1, pdbFileW, (int)_countof(pdbFileW));

    wchar_t keyW[64];
    MultiByteToWideChar(CP_UTF8, 0, key, -1, keyW, (int)_countof(keyW));

    _snwprintf(path, _countof(path), L"/download/symbols/%ls/%ls/%ls", pdbFileW, keyW, pdbFileW);

    printf("[BIN] %s\n", dllFile);
    wprintf(L"[PDB] https://msdl.microsoft.com%ls\n", path);

    if (!download_url_to_file_https(L"msdl.microsoft.com", path, pdbOut)) {
        printf("[PDB] download failed for %s\n", dllFile);
        FreeLibrary(hMod);
        return;
    }

    char fullDllPath[MAX_PATH];
    if (!GetFullPathNameA(dllFile, MAX_PATH, fullDllPath, NULL)) {
        printf("[BIN] GetFullPathNameA failed: %lu\n", GetLastError());
        FreeLibrary(hMod);
        return;
    }

    DWORD64 base = SymLoadModuleEx(
        r->process, NULL, fullDllPath, NULL, (DWORD64)(uintptr_t)hMod, 0, NULL, 0);

    if (!base) {
        printf("[DBG] SymLoadModuleEx failed for %s: %lu\n", dllFile, GetLastError());
        FreeLibrary(hMod);
        return;
    }

    EnumContext ctx = { 0 };
    ctx.moduleForGetProc = hMod;

    if (!init_text_range(&ctx)) {
        printf("[BIN] .text not found: %s\n", dllFile);
        FreeLibrary(hMod);
        return;
    }

    if (!SymEnumSymbols(r->process, base, "*", enum_symbols_cb, &ctx)) {
        printf("[DBG] SymEnumSymbols failed: %lu\n", GetLastError());
    }

    char moduleName[MAX_PATH];
    {
        const char* b = dllFile;
        for (const char* p = dllFile; *p; ++p) if (*p == '\\' || *p == '/') b = p + 1;
        strcpy_s(moduleName, MAX_PATH, b);
    }

#if defined(_M_X64)
    dump_and_merge_records(moduleName, TRUE, AOB_PORT_FORCE_SUPER_PORTABLE, 48);
#elif defined(_M_IX86)
    dump_and_merge_records(moduleName, TRUE, AOB_PORT_FORCE_SUPER_PORTABLE, 32);
#elif defined(_M_ARM64)
    dump_and_merge_records(moduleName, TRUE, AOB_PORT_FORCE_SUPER_PORTABLE, 48);
#else
    dump_and_merge_records(moduleName, TRUE, AOB_PORT_FORCE_SUPER_PORTABLE, 48);
#endif

    SymCleanup(process);

    FreeLibrary(hMod);
}

static void enum_bin_files_in_cwd(void (*on_file)(const char* path, void* user), void* user)
{
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(".\\*.bin", &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        char path[MAX_PATH];
        snprintf(path, sizeof(path), ".\\%s", fd.cFileName);
        on_file(path, user);

    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

int main()
{
    HANDLE process = GetCurrentProcess();

    Runner r = { 0 };
    r.process = process;

    enum_bin_files_in_cwd(process_one_bin, &r);

    print_merged_aob_table_flat_to_file(".\\aob_table.txt");

    free_merged_aob_table();

    system("pause");
    return 0;
}