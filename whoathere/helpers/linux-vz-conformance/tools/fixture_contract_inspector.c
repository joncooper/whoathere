#include <stddef.h>
#include <stdio.h>
#include <string.h>

struct fixture_case_contract {
    const char *fixture_case;
    const char *family;
    const char *expected_terminal;
    const char *trigger_owner;
    const char *action;
    const char *network_policy;
};

static const struct fixture_case_contract fixture_cases[] = {
#define WHOATHERE_FIXTURE_CASE(fixture_case, family, terminal, owner, action, network) \
    {fixture_case, family, terminal, owner, action, network},
#include "fixture_cases.def"
#undef WHOATHERE_FIXTURE_CASE
};

enum {
    fixture_case_count = (int)(sizeof(fixture_cases) / sizeof(fixture_cases[0]))
};

_Static_assert(fixture_case_count == 38, "the fixture contract must contain exactly 38 cases");

static const struct fixture_case_contract *find_fixture_case(const char *name) {
    for (size_t index = 0; index < (size_t)fixture_case_count; ++index) {
        if (strcmp(fixture_cases[index].fixture_case, name) == 0) {
            return &fixture_cases[index];
        }
    }
    return NULL;
}

static void list_fixture_cases(void) {
    for (size_t index = 0; index < (size_t)fixture_case_count; ++index) {
        puts(fixture_cases[index].fixture_case);
    }
}

static void describe_fixture_case(const struct fixture_case_contract *contract) {
    printf(
        "{\"action\":\"%s\",\"case\":\"%s\",\"expected_terminal\":\"%s\","
        "\"external_route\":false,\"family\":\"%s\",\"network_policy\":\"%s\","
        "\"operation\":\"describe_only\",\"package_execution\":false,"
        "\"schema_version\":\"whoathere.linux_vz_inert_fixture_contract.v1\","
        "\"sync_back\":false,\"trigger_owner\":\"%s\"}\n",
        contract->action,
        contract->fixture_case,
        contract->expected_terminal,
        contract->family,
        contract->network_policy,
        contract->trigger_owner
    );
}

static int usage(void) {
    fputs("usage: fixture-contract-inspector --list | --describe CASE\n", stderr);
    return 64;
}

int main(int argument_count, char **arguments) {
    if (argument_count == 2 && strcmp(arguments[1], "--list") == 0) {
        list_fixture_cases();
        return 0;
    }
    if (argument_count == 3 && strcmp(arguments[1], "--describe") == 0) {
        const struct fixture_case_contract *contract = find_fixture_case(arguments[2]);
        if (contract == NULL) {
            fputs("fixture_contract_case_unknown\n", stderr);
            return 65;
        }
        describe_fixture_case(contract);
        return 0;
    }
    return usage();
}
