//go:build nativeget

package get

/*
#include "get.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

func RankMatch(query, target string) int {
	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))
	cTarget := C.CString(target)
	defer C.free(unsafe.Pointer(cTarget))

	score := C.apm_get_rank_match(cQuery, cTarget)
	return int(score)
}

func LoadTargets(targets []string) {
	if len(targets) == 0 {
		return
	}

	cTargets := make([]*C.char, len(targets))
	for i, t := range targets {
		cTargets[i] = C.CString(t)
	}
	defer func() {
		for _, ct := range cTargets {
			C.free(unsafe.Pointer(ct))
		}
	}()

	C.apm_get_load_targets((**C.char)(unsafe.Pointer(&cTargets[0])), C.size_t(len(targets)))
}

func SearchSorted(query string, topN int) []int {
	if topN == 0 {
		return nil
	}

	cQuery := C.CString(query)
	defer C.free(unsafe.Pointer(cQuery))

	outIndices := make([]C.int32_t, topN)
	var outCount C.size_t

	C.apm_get_search_sorted(cQuery, C.size_t(topN), (*C.int32_t)(unsafe.Pointer(&outIndices[0])), &outCount)

	count := int(outCount)
	goResults := make([]int, count)
	for i := 0; i < count; i++ {
		goResults[i] = int(outIndices[i])
	}
	return goResults
}

func LoadVaultJSON(jsonStr string) int {
	cJSON := C.CString(jsonStr)
	defer C.free(unsafe.Pointer(cJSON))
	return int(C.apm_get_load_vault_json(cJSON))
}
