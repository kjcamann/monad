#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sysexits.h>
#include <unistd.h>

#include <yyjson.h>

#include <category/core/assert.h>
#include <category/core/hex.h>
#include <category/core/keccak.h>
#include <category/core/strview.h>
#include <category/rv/code_type.h>
#include <category/rv/rv_code.h>

#include "block_input.h"
#include "input.h"
#include "mem_state_db.h"

struct parse_context
{
    char const *path;
    char const *test_case;
    char specific[256];
};

static thread_local char s_context_buf[2048];

static char const *final_path_component(char const *const path)
{
    char const *last = strrchr(path, '/');
    return last == nullptr ? path : last + 1;
}

char const *describe_context(struct parse_context const *const ctx)
{
    FILE *const file = fmemopen(s_context_buf, sizeof(s_context_buf), "w");
    char const *const filename = final_path_component(ctx->path);

    MONAD_ASSERT(file != nullptr);
    fprintf(file, "parse error in file %s", filename);
    if (ctx->test_case != nullptr) {
        fprintf(file, " [test case `%s`]", ctx->test_case);
    }
    if (ctx->specific[0] != '\0') {
        fprintf(file, " near %s", ctx->specific);
    }
    fclose(file);
    return s_context_buf;
}

static void expect_yyjson_type(
    struct parse_context const *const ctx, yyjson_val *const yy,
    yyjson_type const type, char const *const what)
{
    if (yyjson_get_type(yy) != type) {
        // XXX: need something like yyjson_get_type_desc to be able to translate
        // (type, subtype) to a type description
        errx(
            EX_CONFIG,
            "%s: expected `%s` to have type %s but found value of type %s",
            describe_context(ctx),
            what,
            "<unknown>",
            yyjson_get_type_desc(yy));
    }
}

static struct monad_address parse_address(
    struct parse_context const *const ctx, yyjson_val *const yy,
    char const *const what)
{
    int rc;
    struct monad_address addr;
    char const *const hex = yyjson_get_str(yy);

    expect_yyjson_type(ctx, yy, YYJSON_TYPE_STR, what);
    rc = monad_address_from_hex(hex, yyjson_get_len(yy), &addr);
    if (rc != 0) {
        errx(
            EX_CONFIG,
            "%s: expected `%s` to be an address but could not hex parse `%s`: "
            "%s "
            "(%d)",
            describe_context(ctx),
            what,
            hex,
            strerror(rc),
            rc);
    }
    return addr;
}

static struct monad_bytes32 parse_bytes32(
    struct parse_context const *const ctx, yyjson_val *const yy,
    char const *const what)
{
    int rc;
    struct monad_bytes32 b32;
    size_t parsed_len = sizeof b32;
    char const *const hex = yyjson_get_str(yy);
    size_t const hex_len = yyjson_get_len(yy);

    expect_yyjson_type(ctx, yy, YYJSON_TYPE_STR, what);
    rc = monad_parse_hex(hex, hex_len, &b32, &parsed_len);
    if (rc != 0) {
        errx(
            EX_CONFIG,
            "%s: expected %s to be a bytes32 value but could not hex parse "
            "`%s`: "
            "%s (%d)",
            describe_context(ctx),
            what,
            hex,
            strerror(rc),
            rc);
    }
    if (parsed_len < sizeof b32) {
        __builtin_memmove(b32.bytes + 32 - parsed_len, b32.bytes, parsed_len);
        __builtin_memset(b32.bytes, 0, 32 - parsed_len);
    }
    return b32;
}

static uint64_t parse_uint64(
    struct parse_context const *const ctx, yyjson_val *const yy,
    char const *const what)
{
    int rc;
    struct monad_bytes32 b32;
    uint64_t u;

    b32 = parse_bytes32(ctx, yy, what);
    rc = monad_uint256_be_to_he(&b32, sizeof u, &u);
    if (rc != 0) {
        errx(
            EX_CONFIG,
            "%s: `%s` could not be parsed as uint64_t: %s (%d)",
            describe_context(ctx),
            yyjson_get_str(yy),
            strerror(rc),
            rc);
    }
    return u;
}

static inline yyjson_val *obj_get_or_die(
    struct parse_context const *const ctx, yyjson_val *const obj,
    char const *const name)
{
    yyjson_val *const v = yyjson_obj_get(obj, name);
    if (v == nullptr) {
        errx(
            EX_CONFIG,
            "%s: `%s` not found in object",
            describe_context(ctx),
            name);
    }
    return v;
}

static inline struct monad_address parse_address_from_obj(
    struct parse_context const *const ctx, yyjson_val *const yy_obj,
    char const *const key)
{
    return parse_address(ctx, obj_get_or_die(ctx, yy_obj, key), key);
}

static inline struct monad_bytes32 parse_bytes32_from_obj(
    struct parse_context const *const ctx, yyjson_val *const yy_obj,
    char const *const key)
{
    return parse_bytes32(ctx, obj_get_or_die(ctx, yy_obj, key), key);
}

static inline uint64_t parse_uint64_from_obj(
    struct parse_context const *const ctx, yyjson_val *const yy_obj,
    char const *const key)
{
    return parse_uint64(ctx, yyjson_obj_get(yy_obj, key), key);
}

static void parse_prestate_account_storage(
    struct parse_context *const ctx, yyjson_val *const yy_storage,
    struct monad_address const *const addr, struct storage_map *const storage,
    struct mem_state_db *const mdb)
{
    yyjson_val *yy_key;
    yyjson_obj_iter iter;

    if (yy_storage == nullptr) {
        return;
    }
    expect_yyjson_type(ctx, yy_storage, YYJSON_TYPE_OBJ, "account storage map");

    iter = yyjson_obj_iter_with(yy_storage);
    while ((yy_key = yyjson_obj_iter_next(&iter)) != nullptr) {
        struct monad_bytes32 key;
        struct monad_bytes32 value;
        yyjson_val *const yy_val = yyjson_obj_iter_get_val(yy_key);

        key = parse_bytes32(ctx, yy_key, "storage key");
        value = parse_bytes32(ctx, yy_val, "storage value");
        mem_state_db_set_storage(mdb, addr, storage, &key, &value);
    }
}

static struct monad_bv parse_elf_spec(
    struct parse_context *const ctx, struct monad_sv const spec_sv,
    struct monad_bv *const code_only)
{
    int elf_fd;
    int rc;
    struct stat elf_stat;
    struct monad_rv_code_header *code_header;
    struct monad_sv filename_sv;
    struct monad_sv init_code_hex_sv;
    size_t init_code_len;
    size_t code_only_len;
    ssize_t n_read;
    char filename_buf[2048];

    (void)monad_sv_split_strchr(spec_sv, ',', &filename_sv, &init_code_hex_sv);
    rc = monad_sv_strncpy(filename_buf, sizeof filename_buf, filename_sv);
    if (rc != 0) {
        errx(
            EX_CONFIG,
            "strncpy(3) could not copy filename from `%s`",
            spec_sv.begin);
    }
    init_code_len = monad_sv_len(init_code_hex_sv) / 2;

    elf_fd = open(filename_buf, O_RDONLY);
    if (elf_fd == -1) {
        err(EX_OSERR,
            "%s: could not open(2) ELF transaction data: %s",
            describe_context(ctx),
            filename_buf);
    }
    if (fstat(elf_fd, &elf_stat) == -1) {
        err(EX_OSERR, "could not fstat(2) ELF file %s", filename_buf);
    }

    code_header =
        malloc(sizeof *code_header + (size_t)elf_stat.st_size + init_code_len);
    code_header->code_length = (uint32_t)elf_stat.st_size;

    __builtin_memcpy(
        code_header->prefix,
        MONAD_RV_CODE_PREFIX,
        sizeof MONAD_RV_CODE_PREFIX);
    n_read = read(elf_fd, code_header + 1, code_header->code_length);
    if (n_read == -1) {
        err(EX_OSERR, "read(2) of ELF file %s failed", filename_buf);
    }
    if ((uint32_t)n_read != code_header->code_length) {
        errx(EX_OSERR, "short read(2) of ELF file %s", filename_buf);
    }
    code_only_len = sizeof *code_header + code_header->code_length;

    rc = monad_parse_hex(
        init_code_hex_sv.begin,
        monad_sv_len(init_code_hex_sv),
        (uint8_t *)(code_header + 1) + code_header->code_length,
        &init_code_len);
    if (rc != 0) {
        errx(
            EX_CONFIG,
            "parse error in ELF init code: %s",
            init_code_hex_sv.begin);
    }
    if (code_only != nullptr) {
        *code_only = monad_bv_from_size(code_header, code_only_len);
    }
    return monad_bv_from_size(code_header, code_only_len + init_code_len);
}

static void parse_account_code(
    struct parse_context *const ctx, yyjson_val *const yy_code,
    struct monad_bytes32 *const code_hash, struct mem_state_db *const mdb)
{
    int rc;
    char const *code_text;
    size_t code_text_len;
    struct monad_bv code;

    if (yy_code == nullptr) {
        *code_hash = MONAD_BYTES32_EMPTY_KECCAK;
        return;
    }
    expect_yyjson_type(ctx, yy_code, YYJSON_TYPE_STR, "account code");
    code_text = yyjson_get_str(yy_code);
    code_text_len = yyjson_get_len(yy_code);
    if (code_text_len > 4 && strncmp(code_text, "ELF:", 4) == 0) {
        (void)parse_elf_spec(ctx, monad_sv_from_cstr(code_text + 4), &code);
    }
    else {
        void *codebuf;
        size_t codebuf_len;

        codebuf_len = code_text_len / 2;
        codebuf = malloc(codebuf_len);
        if (codebuf == nullptr) {
            err(EX_OSERR, "malloc(3) of code buffer failed");
        }
        rc = monad_parse_hex(code_text, code_text_len, codebuf, &codebuf_len);
        if (rc != 0) {
            errx(
                EX_CONFIG,
                "%s: unable to parse code: %s (%d)",
                describe_context(ctx),
                strerror(rc),
                rc);
        }
        code = monad_bv_from_size(codebuf, codebuf_len);
    }
    if (!monad_bv_empty(code)) {
        keccak256(code.begin, monad_bv_len(code), code_hash->bytes);
        mem_state_db_set_code(mdb, code_hash, code);
    }
    free((void *)code.begin);
}

static void parse_prestate_account(
    struct parse_context *const ctx, yyjson_val *const yy_account,
    struct monad_address *const addr, struct mem_state_db *const mdb)
{
    struct monad_eth_account_state acct_state;
    struct storage_map *storage;
    yyjson_val *yy_balance;
    yyjson_val *yy_nonce;

    expect_yyjson_type(
        ctx, yy_account, YYJSON_TYPE_OBJ, "prestate account entry");

    yy_balance = yyjson_obj_get(yy_account, "balance");
    acct_state.balance = yy_balance != nullptr
                             ? parse_bytes32(ctx, yy_balance, "account balance")
                             : MONAD_BYTES32_ZERO;

    yy_nonce = yyjson_obj_get(yy_account, "nonce");
    acct_state.nonce =
        yy_nonce != nullptr ? parse_uint64(ctx, yy_nonce, "nonce") : 0;

    parse_account_code(
        ctx, yyjson_obj_get(yy_account, "code"), &acct_state.code_hash, mdb);
    mem_state_db_set_account(mdb, addr, &acct_state, &storage);
    parse_prestate_account_storage(
        ctx, yyjson_obj_get(yy_account, "storage"), addr, storage, mdb);
}

static void parse_prestate(
    struct parse_context *const ctx, yyjson_val *const yy_prestate,
    struct sim_input *const si)
{
    struct mem_state_db_config config;
    yyjson_val *yy_addr_key;
    yyjson_obj_iter iter;

    if (yy_prestate == nullptr) {
        return;
    }

    snprintf(ctx->specific, sizeof ctx->specific, "prestate dictionary");
    expect_yyjson_type(ctx, yy_prestate, YYJSON_TYPE_OBJ, "prestate spec");

    config.expected_accounts = yyjson_obj_size(yy_prestate);
    config.expected_code_accounts = config.expected_accounts / 2;
    config.expected_storage_slots_per_account = 4;
    si->overlay = mem_state_db_create(&config);

    iter = yyjson_obj_iter_with(yy_prestate);
    while ((yy_addr_key = yyjson_obj_iter_next(&iter)) != nullptr) {
        int rc;
        struct monad_address acct_addr;
        rc = monad_address_from_hex(
            yyjson_get_str(yy_addr_key),
            yyjson_get_len(yy_addr_key),
            &acct_addr);
        if (rc != 0) {
            errx(
                EX_CONFIG,
                "%s: could not parse account address `%s`: %s (%d)",
                describe_context(ctx),
                yyjson_get_str(yy_addr_key),
                strerror(rc),
                rc);
        }
        snprintf(
            ctx->specific,
            sizeof ctx->specific,
            "prestate for account %s",
            monad_address_to_hex_static(&acct_addr));
        parse_prestate_account(
            ctx, yyjson_obj_iter_get_val(yy_addr_key), &acct_addr, si->overlay);
    }
}

static void parse_block_header(
    struct parse_context *const ctx, yyjson_val *const yy_header,
    struct monad_eth_block_input *const eth_input,
    struct monad_bytes32 *const parent_hash)
{
    uint64_t nonce;

    expect_yyjson_type(ctx, yy_header, YYJSON_TYPE_OBJ, "block header");
    eth_input->base_fee_per_gas =
        parse_bytes32_from_obj(ctx, yy_header, "baseFeePerGas");
    eth_input->beneficiary = parse_address_from_obj(ctx, yy_header, "coinbase");
    eth_input->difficulty = parse_uint64_from_obj(ctx, yy_header, "difficulty");
    eth_input->gas_limit = parse_uint64_from_obj(ctx, yy_header, "gasLimit");
    eth_input->prev_randao = parse_bytes32_from_obj(ctx, yy_header, "mixHash");
    nonce = parse_uint64_from_obj(ctx, yy_header, "nonce");
    __builtin_memcpy(&eth_input->nonce, &nonce, sizeof nonce);
    eth_input->number = parse_uint64_from_obj(ctx, yy_header, "number");
    eth_input->timestamp = parse_uint64_from_obj(ctx, yy_header, "timestamp");
    eth_input->ommers_hash =
        parse_bytes32_from_obj(ctx, yy_header, "uncleHash");
    eth_input->transactions_root =
        parse_bytes32_from_obj(ctx, yy_header, "transactionsTrie");
    eth_input->withdrawals_root =
        parse_bytes32_from_obj(ctx, yy_header, "withdrawalsRoot");
    if (parent_hash != nullptr) {
        *parent_hash = parse_bytes32_from_obj(ctx, yy_header, "parentHash");
    }
}

static void parse_txn(
    struct parse_context *const ctx, yyjson_val *const yy_txn,
    struct txn_input *const ti)
{
    struct monad_eth_txn_header *header = &ti->header;
    yyjson_val *yy_to;
    yyjson_val *yy_data;
    char const *data;
    size_t data_len;

    expect_yyjson_type(ctx, yy_txn, YYJSON_TYPE_OBJ, "transaction");
    header->txn_type = MONAD_TXN_LEGACY; // XXX: not sure how to set?
    header->gas_limit = parse_uint64_from_obj(ctx, yy_txn, "gasLimit");
    header->max_fee_per_gas = parse_bytes32_from_obj(ctx, yy_txn, "gasPrice");
    header->nonce = parse_uint64_from_obj(ctx, yy_txn, "nonce");
    header->r = parse_bytes32_from_obj(ctx, yy_txn, "r");
    header->s = parse_bytes32_from_obj(ctx, yy_txn, "s");
    header->value = parse_bytes32_from_obj(ctx, yy_txn, "value");

    yy_to = obj_get_or_die(ctx, yy_txn, "to");
    header->is_contract_creation = yyjson_get_len(yy_to) == 0;
    header->to = header->is_contract_creation ? MONAD_ADDRESS_ZERO
                                              : parse_address(ctx, yy_to, "to");
    ti->sender = parse_address_from_obj(ctx, yy_txn, "sender");
    yy_data = obj_get_or_die(ctx, yy_txn, "data");
    data = yyjson_get_str(yy_data);
    data_len = yyjson_get_len(yy_data);
    if (data_len > 4 && strncmp(data, "ELF:", 4) == 0) {
        ti->data = parse_elf_spec(ctx, monad_sv_from_cstr(data + 4), nullptr);
    }
    else {
        int rc;
        size_t databuf_len = data_len / 2;
        void *databuf = malloc(databuf_len);

        if (databuf == nullptr) {
            err(EX_OSERR, "malloc(3) failed for transaction data");
        }
        rc = monad_parse_hex(data, data_len, databuf, &databuf_len);
        if (rc != 0) {
            errx(
                EX_CONFIG,
                "%s: could not parse transaction data: %s (%d)",
                describe_context(ctx),
                strerror(rc),
                rc);
        }
        ti->data = monad_bv_from_size(databuf, databuf_len);
    }
}

static void parse_block_txns(
    struct parse_context *const ctx, yyjson_val *const yy_txns,
    size_t const block_number, struct block_input *const bi)
{
    expect_yyjson_type(ctx, yy_txns, YYJSON_TYPE_ARR, "transactions array");

    bi->txn_count = yyjson_arr_size(yy_txns);
    bi->txns = calloc(bi->txn_count, sizeof(struct txn_input));
    if (bi->txns == nullptr) {
        err(EX_OSERR, "malloc(3) of block transactions failed");
    }
    for (size_t i = 0; i < bi->txn_count; ++i) {
        snprintf(
            ctx->specific,
            sizeof ctx->specific,
            "txn %zu:%zu",
            block_number,
            i);
        parse_txn(
            ctx, yyjson_arr_get(yy_txns, i), (struct txn_input *)&bi->txns[i]);
    }
}

static void parse_block(
    struct parse_context *const ctx, yyjson_val *const yy_block,
    struct block_input *const bi)
{
    expect_yyjson_type(ctx, yy_block, YYJSON_TYPE_OBJ, "block");
    parse_block_header(
        ctx,
        obj_get_or_die(ctx, yy_block, "blockHeader"),
        &bi->eth_block_input,
        &bi->parent_hash);

    snprintf(
        ctx->specific,
        sizeof ctx->specific,
        "block %lu",
        (unsigned long)bi->eth_block_input.number);
    parse_block_txns(
        ctx,
        obj_get_or_die(ctx, yy_block, "transactions"),
        bi->eth_block_input.number,
        bi);
}

static void parse_blocks(
    struct parse_context *const ctx, yyjson_val *const yy_blocks,
    struct sim_input *const si)
{
    expect_yyjson_type(ctx, yy_blocks, YYJSON_TYPE_ARR, "blocks array");
    si->block_count = yyjson_arr_size(yy_blocks);
    si->blocks = calloc(si->block_count, sizeof(struct block_input));
    if (si->blocks == nullptr) {
        err(EX_OSERR, "malloc(3) of %zu block inputs failed", si->block_count);
    }

    for (size_t i = 0; i < si->block_count; ++i) {
        snprintf(
            ctx->specific, sizeof ctx->specific, "blocks array entry %zu", i);
        parse_block(
            ctx,
            yyjson_arr_get(yy_blocks, i),
            (struct block_input *)&si->blocks[i]);
    }
}

static struct sim_input *parse_eth_test_case(
    struct parse_context *const ctx, yyjson_val *const yy_name,
    yyjson_val *const yy_test_case)
{
    int rc;
    struct sim_input *si;
    yyjson_val *yy_key;
    yyjson_obj_iter iter;

    expect_yyjson_type(ctx, yy_test_case, YYJSON_TYPE_OBJ, "test case");
    si = malloc(sizeof *si);
    if (si == nullptr) {
        err(EX_OSERR, "malloc(3) of sim_input failed");
    }
    memset(si, 0, sizeof *si);
    ctx->test_case = yyjson_get_str(yy_name);
    snprintf(
        ctx->specific, sizeof ctx->specific, "test case %s", ctx->test_case);
    rc = asprintf(
        (char **)&si->description,
        "test case %s:%s",
        ctx->path,
        ctx->test_case);
    MONAD_ASSERT(rc >= 0);

    iter = yyjson_obj_iter_with(yy_test_case);
    while ((yy_key = yyjson_obj_iter_next(&iter)) != nullptr) {
        char const *const key_text = yyjson_get_str(yy_key);
        if (strcmp(key_text, "pre") == 0) {
            parse_prestate(ctx, yyjson_obj_iter_get_val(yy_key), si);
        }
        else if (strcmp(key_text, "blocks") == 0) {
            parse_blocks(ctx, yyjson_obj_iter_get_val(yy_key), si);
        }
        else if (strcmp(key_text, "genesisBlockHeader") == 0) {
            parse_block_header(
                ctx,
                yyjson_obj_iter_get_val(yy_key),
                &si->genesis_block_header,
                nullptr);
        }
    }

    return si;
}

static struct sim_input_list
parse_eth_test_doc(struct parse_context *const ctx, yyjson_val *const yy_root)
{
    struct sim_input_list inputs;
    yyjson_obj_iter iter;
    yyjson_val *yy_key;

    expect_yyjson_type(ctx, yy_root, YYJSON_TYPE_OBJ, "root object");
    STAILQ_INIT(&inputs);

    // Each key in the Ethereum testcase root level object is a test name
    iter = yyjson_obj_iter_with(yy_root);
    while ((yy_key = yyjson_obj_iter_next(&iter)) != nullptr) {
        struct sim_input *const si =
            parse_eth_test_case(ctx, yy_key, yyjson_obj_iter_get_val(yy_key));
        STAILQ_INSERT_TAIL(&inputs, si, next);
    }

    return inputs;
}

struct sim_input_list sim_input_load_eth_test(char const *const path)
{
    struct sim_input_list inputs;
    yyjson_doc *doc;
    yyjson_read_err err;
    struct parse_context ctx = {};

    ctx.path = path;
    doc = yyjson_read_file(path, YYJSON_READ_NOFLAG, nullptr, &err);
    if (doc == nullptr) {
        errx(
            EX_UNAVAILABLE,
            "JSON read error in %s: %s (%u) at byte position %zu\n",
            path,
            err.msg,
            err.code,
            err.pos);
    }
    inputs = parse_eth_test_doc(&ctx, yyjson_doc_get_root(doc));
    yyjson_doc_free(doc);
    return inputs;
}
