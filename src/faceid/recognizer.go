//go:build faceid

package faceid

/*
#include "faceid.h"
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"math"
	"unsafe"
)

var ThresholdByProfile = map[string]float32{
	"standard": 0.45,
	"hardened": 0.38,
	"paranoid": 0.32,
	"legacy":   0.45,
}

var ErrNoCamera = fmt.Errorf("no camera found")

const (
	DefaultThreshold = 0.45
	errBufSize       = 2048
)

type Recognizer struct {
	handle *C.FaceIdHandle
}

func NewRecognizer(modelsDir string) (*Recognizer, error) {
	cModelsDir := C.CString(modelsDir)
	defer C.free(unsafe.Pointer(cModelsDir))

	errBuf := make([]C.char, errBufSize)
	var handle *C.FaceIdHandle
	if code := C.faceid_init(cModelsDir, &handle, &errBuf[0], C.size_t(len(errBuf))); code != 0 {
		return nil, fmt.Errorf("failed to init face recognizer (models dir: %s): %s", modelsDir, cStringFromBuf(errBuf))
	}
	if handle == nil {
		return nil, fmt.Errorf("failed to init face recognizer (models dir: %s): native handle was nil", modelsDir)
	}
	return &Recognizer{handle: handle}, nil
}

func (r *Recognizer) Close() {
	if r != nil && r.handle != nil {
		C.faceid_teardown(r.handle)
		r.handle = nil
	}
}

func (r *Recognizer) Enroll(numFrames int) ([]float32, [][]float32, error) {
	if r == nil || r.handle == nil {
		return nil, nil, fmt.Errorf("face recognizer is closed")
	}
	if numFrames < 5 {
		numFrames = 12
	}

	errBuf := make([]C.char, errBufSize)
	var result C.FaceIdEmbeddingResult
	defer C.faceid_free_result(&result)

	if code := C.faceid_enroll(r.handle, C.int32_t(numFrames), &result, &errBuf[0], C.size_t(len(errBuf))); code != 0 {
		return nil, nil, nativeError(code, errBuf)
	}

	embedding := floatsFromNative(result.embedding, result.embedding_len)
	samples := sampleMatrixFromNative(result.samples, result.samples_len, result.sample_count)
	return embedding, samples, nil
}

func (r *Recognizer) Verify(stored [][]float32, securityProfile string) (bool, float32, error) {
	return r.VerifyWithContext(context.Background(), stored, securityProfile, 24)
}

func (r *Recognizer) VerifyWithContext(ctx context.Context, stored [][]float32, securityProfile string, maxFrames int) (bool, float32, error) {
	if r == nil || r.handle == nil {
		return false, 0, fmt.Errorf("face recognizer is closed")
	}
	if len(stored) == 0 {
		return false, 0, fmt.Errorf("no stored face embeddings")
	}
	if maxFrames <= 0 {
		maxFrames = 24
	}
	select {
	case <-ctx.Done():
		return false, 0, fmt.Errorf("verification cancelled")
	default:
	}

	flat := flattenEmbeddings(stored)
	if len(flat) == 0 {
		return false, 0, fmt.Errorf("no stored face embeddings")
	}

	cProfile := C.CString(securityProfile)
	defer C.free(unsafe.Pointer(cProfile))

	errBuf := make([]C.char, errBufSize)
	var result C.FaceIdEmbeddingResult
	defer C.faceid_free_result(&result)

	code := C.verify_face(
		r.handle,
		(*C.float)(unsafe.Pointer(&flat[0])),
		C.size_t(len(flat)),
		C.size_t(len(stored)),
		cProfile,
		C.int32_t(maxFrames),
		&result,
		&errBuf[0],
		C.size_t(len(errBuf)),
	)
	if code != 0 {
		return false, 0, nativeError(code, errBuf)
	}

	select {
	case <-ctx.Done():
		return false, float32(result.confidence), fmt.Errorf("verification cancelled")
	default:
	}
	return bool(result.matched), float32(result.confidence), nil
}

func cStringFromBuf(buf []C.char) string {
	if len(buf) == 0 {
		return ""
	}
	return C.GoString(&buf[0])
}

func nativeError(code C.int32_t, buf []C.char) error {
	msg := cStringFromBuf(buf)
	if msg == "" {
		msg = fmt.Sprintf("native faceid error %d", int32(code))
	}
	if msg == "no camera found" {
		return ErrNoCamera
	}
	return fmt.Errorf("%s", msg)
}

func floatsFromNative(ptr *C.float, n C.size_t) []float32 {
	count := int(n)
	if ptr == nil || count <= 0 {
		return nil
	}
	src := unsafe.Slice((*float32)(unsafe.Pointer(ptr)), count)
	out := make([]float32, count)
	copy(out, src)
	return out
}

func sampleMatrixFromNative(ptr *C.float, total C.size_t, sampleCount C.size_t) [][]float32 {
	flat := floatsFromNative(ptr, total)
	count := int(sampleCount)
	if len(flat) == 0 || count <= 0 {
		return nil
	}
	width := len(flat) / count
	if width == 0 {
		return nil
	}

	samples := make([][]float32, 0, count)
	for i := 0; i < count; i++ {
		start := i * width
		end := start + width
		if end > len(flat) {
			break
		}
		sample := make([]float32, width)
		copy(sample, flat[start:end])
		samples = append(samples, sample)
	}
	return samples
}

func flattenEmbeddings(embeddings [][]float32) []float32 {
	var flat []float32
	for _, emb := range embeddings {
		if len(emb) == 0 {
			continue
		}
		flat = append(flat, emb...)
	}
	return flat
}

func cosineDistance(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 1.0
	}

	var dotProduct, normA, normB float64
	for i := range a {
		dotProduct += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		normB += float64(b[i]) * float64(b[i])
	}

	if normA == 0 || normB == 0 {
		return 1.0
	}

	similarity := dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
	return float32(1.0 - similarity)
}
