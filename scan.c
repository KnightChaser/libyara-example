#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <yara.h>

int callback_function(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = (YR_RULE*) message_data;
        printf("Matched rule: %s\n", rule->identifier);

        // Print meta data
        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            printf("Meta %s = ", meta->identifier);
            if (meta->type == META_TYPE_INTEGER) {
                printf("%" PRId64 "\n", meta->integer);
            } else if (meta->type == META_TYPE_STRING) {
                printf("%s\n", meta->string);
            } else if (meta->type == META_TYPE_BOOLEAN) {
                printf("%s\n", meta->integer ? "true" : "false");
            }
        }

        // Print matched strings
        YR_STRING* string;
        yr_rule_strings_foreach(rule, string) {
            YR_MATCH* match;
            yr_string_matches_foreach(context, string, match) {
                printf("String %s matched at offset %" PRId64 "\n", string->identifier, match->base + match->offset);
            }
        }

    } else if (message == CALLBACK_MSG_RULE_NOT_MATCHING) {
        printf("No rule matched.\n");
    }
    return CALLBACK_CONTINUE;
}

int main(int argc, char** argv) {
    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to initialize YARA.\n");
        return 1;
    }

    YR_COMPILER* compiler = NULL;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to create YARA compiler.\n");
        yr_finalize();
        return 1;
    }

    FILE* rule_file = fopen("hello_world.yara", "r");
    if (!rule_file) {
        fprintf(stderr, "Failed to open rule file.\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }

    int errors = yr_compiler_add_file(compiler, rule_file, NULL, NULL);
    fclose(rule_file);

    if (errors > 0) {
        fprintf(stderr, "Error(s) compiling the YARA rule.\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }

    YR_RULES* rules = NULL;
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to get compiled rules.\n");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return 1;
    }

    yr_compiler_destroy(compiler);

    const char* target_file = "hello_world.out";
    int scan_result = yr_rules_scan_file(rules, target_file, 0, callback_function, NULL, 0);

    if (scan_result != ERROR_SUCCESS) {
        fprintf(stderr, "Error scanning file.\n");
        yr_rules_destroy(rules);
        yr_finalize();
        return 1;
    }

    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}

