#ifndef APM_FACEID_H
#define APM_FACEID_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FaceIdHandle FaceIdHandle;

typedef struct FaceIdEmbeddingResult {
  float *embedding;
  size_t embedding_len;
  float *samples;
  size_t samples_len;
  size_t sample_count;
  float confidence;
  bool matched;
} FaceIdEmbeddingResult;

int32_t faceid_init(const char *models_dir, FaceIdHandle **out, char *err_buf, size_t err_buf_len);
void faceid_teardown(FaceIdHandle *handle);

int32_t faceid_enroll(
    FaceIdHandle *handle,
    int32_t num_frames,
    FaceIdEmbeddingResult *out,
    char *err_buf,
    size_t err_buf_len);

int32_t verify_face(
    FaceIdHandle *handle,
    const float *stored_embeddings,
    size_t stored_len,
    size_t stored_count,
    const char *security_profile,
    int32_t max_frames,
    FaceIdEmbeddingResult *out,
    char *err_buf,
    size_t err_buf_len);

void faceid_free_result(FaceIdEmbeddingResult *result);

#ifdef __cplusplus
}
#endif

#endif
