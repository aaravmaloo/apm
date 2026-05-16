#ifndef APM_GET_H
#define APM_GET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t apm_get_rank_match(const char* query, const char* target);
void apm_get_load_targets(const char** targets, size_t count);
void apm_get_search_sorted(const char* query, size_t top_n, int32_t* out_indices, size_t* out_count);
int32_t apm_get_load_vault_json(const char* json_str);

#ifdef __cplusplus
}
#endif

#endif
