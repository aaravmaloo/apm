use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_float};
use std::ptr;
use std::slice;
use std::thread;
use std::time::Duration;

use image::{imageops::FilterType, GrayImage, ImageBuffer, Luma, RgbImage};
use nokhwa::{
    pixel_format::RgbFormat,
    utils::{CameraIndex, RequestedFormat, RequestedFormatType},
    Camera,
};

const EMBEDDING_SIDE: u32 = 16;
const EMBEDDING_LEN: usize = (EMBEDDING_SIDE * EMBEDDING_SIDE) as usize;
const DEFAULT_THRESHOLD: f32 = 0.45;
const ENROLL_MIN_CLEAN: usize = 5;
const ENROLL_MAX_SPREAD: f32 = 0.24;
const VERIFY_MAX_SPREAD: f32 = 0.30;
const VERIFY_MIN_CLEAN: usize = 3;
const VERIFY_THRESHOLD_BUMP: f32 = 0.06;

#[repr(C)]
pub struct FaceIdHandle {
    _reserved: u8,
}

#[repr(C)]
pub struct FaceIdEmbeddingResult {
    embedding: *mut c_float,
    embedding_len: usize,
    samples: *mut c_float,
    samples_len: usize,
    sample_count: usize,
    confidence: c_float,
    matched: bool,
}

impl Default for FaceIdEmbeddingResult {
    fn default() -> Self {
        Self {
            embedding: ptr::null_mut(),
            embedding_len: 0,
            samples: ptr::null_mut(),
            samples_len: 0,
            sample_count: 0,
            confidence: 0.0,
            matched: false,
        }
    }
}

struct NativeError {
    code: i32,
    message: String,
}

type NativeResult<T> = Result<T, NativeError>;

#[no_mangle]
pub unsafe extern "C" fn faceid_init(
    _models_dir: *const c_char,
    out: *mut *mut FaceIdHandle,
    err_buf: *mut c_char,
    err_buf_len: usize,
) -> i32 {
    catch_status(err_buf, err_buf_len, || {
        if out.is_null() {
            return Err(err(2, "output handle pointer is null"));
        }
        *out = Box::into_raw(Box::new(FaceIdHandle { _reserved: 0 }));
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn faceid_teardown(handle: *mut FaceIdHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

#[no_mangle]
pub unsafe extern "C" fn faceid_enroll(
    handle: *mut FaceIdHandle,
    num_frames: i32,
    out: *mut FaceIdEmbeddingResult,
    err_buf: *mut c_char,
    err_buf_len: usize,
) -> i32 {
    catch_status(err_buf, err_buf_len, || {
        handle_ref(handle)?;
        if out.is_null() {
            return Err(err(2, "result pointer is null"));
        }

        let target_frames = if num_frames < 5 {
            12
        } else {
            num_frames as usize
        };
        let mut camera = open_camera()?;
        let mut embeddings = Vec::with_capacity(target_frames);

        while embeddings.len() < target_frames {
            let embedding = capture_embedding(&mut camera)?;
            embeddings.push(embedding);
            thread::sleep(Duration::from_millis(90));
        }

        let embeddings = keep_consistent_embeddings(&embeddings, ENROLL_MAX_SPREAD);
        if embeddings.len() < ENROLL_MIN_CLEAN {
            return Err(err(
                5,
                format!(
                    "insufficient consistent face frames: got {}, need at least {}",
                    embeddings.len(),
                    ENROLL_MIN_CLEAN
                ),
            ));
        }

        let average = average_embeddings(&embeddings);
        let templates = build_verification_templates(&embeddings);
        write_result(out, average, templates, false, 0.0);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn verify_face(
    handle: *mut FaceIdHandle,
    stored_embeddings: *const c_float,
    stored_len: usize,
    stored_count: usize,
    security_profile: *const c_char,
    max_frames: i32,
    out: *mut FaceIdEmbeddingResult,
    err_buf: *mut c_char,
    err_buf_len: usize,
) -> i32 {
    catch_status(err_buf, err_buf_len, || {
        handle_ref(handle)?;
        if out.is_null() {
            return Err(err(2, "result pointer is null"));
        }

        let stored = read_stored_embeddings(stored_embeddings, stored_len, stored_count)?;
        let profile = cstr_to_string(security_profile).unwrap_or_default();
        let mut threshold = threshold_for_profile(&profile);
        if threshold < DEFAULT_THRESHOLD {
            threshold += 0.02;
        }

        let max_frames = if max_frames <= 0 {
            24
        } else {
            max_frames as usize
        };
        let mut camera = open_camera()?;
        let mut best_confidence = 0.0_f32;
        let mut live_embeddings = Vec::new();

        for _ in 0..max_frames {
            let live = capture_embedding(&mut camera)?;
            let dist = best_embedding_distance(&stored, &live);
            let confidence = 1.0 - dist;
            best_confidence = best_confidence.max(confidence);

            if dist < threshold {
                write_result(out, live, Vec::new(), true, confidence);
                return Ok(());
            }

            live_embeddings.push(live);
            let stable = keep_consistent_embeddings(&live_embeddings, VERIFY_MAX_SPREAD);
            if stable.len() >= VERIFY_MIN_CLEAN {
                let average = average_embeddings(&stable);
                let stable_dist = best_embedding_distance(&stored, &average);
                let stable_confidence = 1.0 - stable_dist;
                best_confidence = best_confidence.max(stable_confidence);
                if stable_dist < threshold + VERIFY_THRESHOLD_BUMP {
                    write_result(out, average, Vec::new(), true, stable_confidence);
                    return Ok(());
                }
            }

            thread::sleep(Duration::from_millis(30));
        }

        write_result(out, Vec::new(), Vec::new(), false, best_confidence);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn faceid_free_result(result: *mut FaceIdEmbeddingResult) {
    if result.is_null() {
        return;
    }
    let result = &mut *result;
    if !result.embedding.is_null() && result.embedding_len > 0 {
        drop(Vec::from_raw_parts(
            result.embedding,
            result.embedding_len,
            result.embedding_len,
        ));
    }
    if !result.samples.is_null() && result.samples_len > 0 {
        drop(Vec::from_raw_parts(
            result.samples,
            result.samples_len,
            result.samples_len,
        ));
    }
    *result = FaceIdEmbeddingResult::default();
}

fn open_camera() -> NativeResult<Camera> {
    let requested =
        RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
    let mut camera =
        Camera::new(CameraIndex::Index(0), requested).map_err(|e| err(1, e.to_string()))?;
    camera.open_stream().map_err(|e| err(1, e.to_string()))?;
    Ok(camera)
}

fn capture_embedding(camera: &mut Camera) -> NativeResult<Vec<f32>> {
    let frame = camera.frame().map_err(|e| err(1, e.to_string()))?;
    let decoded = frame
        .decode_image::<RgbFormat>()
        .map_err(|e| err(6, e.to_string()))?;
    Ok(embedding_from_rgb(&decoded))
}

fn embedding_from_rgb(image: &RgbImage) -> Vec<f32> {
    let (width, height) = image.dimensions();
    let crop_size = width.min(height).max(1);
    let crop_x = (width.saturating_sub(crop_size)) / 2;
    let crop_y = (height.saturating_sub(crop_size)) / 2;
    let crop = image::imageops::crop_imm(image, crop_x, crop_y, crop_size, crop_size).to_image();
    let gray = rgb_to_gray(&crop);
    let small =
        image::imageops::resize(&gray, EMBEDDING_SIDE, EMBEDDING_SIDE, FilterType::Triangle);

    let mut values = Vec::with_capacity(EMBEDDING_LEN);
    for pixel in small.pixels() {
        values.push(pixel[0] as f32 / 255.0);
    }
    normalize_embedding(&mut values);
    values
}

fn rgb_to_gray(image: &RgbImage) -> GrayImage {
    let (width, height) = image.dimensions();
    ImageBuffer::from_fn(width, height, |x, y| {
        let p = image.get_pixel(x, y);
        let value = (0.299 * p[0] as f32 + 0.587 * p[1] as f32 + 0.114 * p[2] as f32) as u8;
        Luma([value])
    })
}

fn normalize_embedding(values: &mut [f32]) {
    if values.is_empty() {
        return;
    }
    let mean = values.iter().sum::<f32>() / values.len() as f32;
    let variance = values
        .iter()
        .map(|v| {
            let d = *v - mean;
            d * d
        })
        .sum::<f32>()
        / values.len() as f32;
    let stddev = variance.sqrt().max(0.0001);
    for value in values {
        *value = (*value - mean) / stddev;
    }
}

fn read_stored_embeddings(
    ptr: *const c_float,
    total_len: usize,
    count: usize,
) -> NativeResult<Vec<Vec<f32>>> {
    if ptr.is_null() || total_len == 0 || count == 0 {
        return Err(err(2, "no stored face embeddings"));
    }
    let flat = unsafe { slice::from_raw_parts(ptr, total_len) };
    let width = total_len / count;
    if width == 0 || width * count != total_len {
        return Err(err(2, "stored face embeddings have invalid dimensions"));
    }
    Ok(flat.chunks(width).map(|chunk| chunk.to_vec()).collect())
}

fn threshold_for_profile(profile: &str) -> f32 {
    match profile {
        "hardened" => 0.38,
        "paranoid" => 0.32,
        "standard" | "legacy" => 0.45,
        _ => DEFAULT_THRESHOLD,
    }
}

fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 1.0;
    }
    let mut dot = 0.0_f64;
    let mut norm_a = 0.0_f64;
    let mut norm_b = 0.0_f64;
    for (av, bv) in a.iter().zip(b.iter()) {
        let av = *av as f64;
        let bv = *bv as f64;
        dot += av * bv;
        norm_a += av * av;
        norm_b += bv * bv;
    }
    if norm_a == 0.0 || norm_b == 0.0 {
        return 1.0;
    }
    (1.0 - dot / (norm_a.sqrt() * norm_b.sqrt())) as f32
}

fn best_embedding_distance(stored: &[Vec<f32>], live: &[f32]) -> f32 {
    stored
        .iter()
        .map(|candidate| cosine_distance(candidate, live))
        .fold(1.0_f32, f32::min)
}

fn average_embeddings(embeddings: &[Vec<f32>]) -> Vec<f32> {
    if embeddings.is_empty() {
        return Vec::new();
    }
    let width = embeddings[0].len();
    let mut avg = vec![0.0_f32; width];
    for embedding in embeddings {
        for (i, value) in embedding.iter().enumerate().take(width) {
            avg[i] += *value;
        }
    }
    for value in &mut avg {
        *value /= embeddings.len() as f32;
    }
    avg
}

fn keep_consistent_embeddings(embeddings: &[Vec<f32>], max_distance: f32) -> Vec<Vec<f32>> {
    if embeddings.len() <= ENROLL_MIN_CLEAN {
        return embeddings.to_vec();
    }

    let mut best_index = None;
    let mut best_neighbors = 0_usize;
    for (i, embedding) in embeddings.iter().enumerate() {
        let neighbors = embeddings
            .iter()
            .filter(|candidate| cosine_distance(embedding, candidate) <= max_distance)
            .count();
        if neighbors > best_neighbors {
            best_neighbors = neighbors;
            best_index = Some(i);
        }
    }

    let Some(best_index) = best_index else {
        return Vec::new();
    };
    let reference = &embeddings[best_index];
    embeddings
        .iter()
        .filter(|embedding| cosine_distance(reference, embedding) <= max_distance)
        .cloned()
        .collect()
}

fn build_verification_templates(embeddings: &[Vec<f32>]) -> Vec<Vec<f32>> {
    let mut templates: Vec<Vec<f32>> = Vec::new();
    for embedding in embeddings {
        let duplicate = templates
            .iter()
            .any(|existing| cosine_distance(existing, embedding) <= VERIFY_MAX_SPREAD);
        if !duplicate {
            templates.push(embedding.clone());
        }
    }
    if templates.is_empty() && !embeddings.is_empty() {
        templates.push(average_embeddings(embeddings));
    }
    templates
}

fn write_result(
    out: *mut FaceIdEmbeddingResult,
    embedding: Vec<f32>,
    samples: Vec<Vec<f32>>,
    matched: bool,
    confidence: f32,
) {
    unsafe {
        faceid_free_result(out);
        let result = &mut *out;

        let mut embedding = embedding;
        result.embedding_len = embedding.len();
        result.embedding = if embedding.is_empty() {
            ptr::null_mut()
        } else {
            let ptr = embedding.as_mut_ptr();
            std::mem::forget(embedding);
            ptr
        };

        let sample_count = samples.len();
        let mut flat_samples: Vec<f32> = samples.into_iter().flatten().collect();
        result.samples_len = flat_samples.len();
        result.sample_count = sample_count;
        result.samples = if flat_samples.is_empty() {
            ptr::null_mut()
        } else {
            let ptr = flat_samples.as_mut_ptr();
            std::mem::forget(flat_samples);
            ptr
        };
        result.matched = matched;
        result.confidence = confidence;
    }
}

fn catch_status<F>(err_buf: *mut c_char, err_buf_len: usize, f: F) -> i32
where
    F: FnOnce() -> NativeResult<()>,
{
    match f() {
        Ok(()) => {
            write_error(err_buf, err_buf_len, "");
            0
        }
        Err(e) => {
            write_error(err_buf, err_buf_len, &e.message);
            e.code
        }
    }
}

fn handle_ref<'a>(handle: *mut FaceIdHandle) -> NativeResult<&'a FaceIdHandle> {
    if handle.is_null() {
        return Err(err(2, "face recognizer handle is null"));
    }
    Ok(unsafe { &*handle })
}

fn cstr_to_string(ptr: *const c_char) -> NativeResult<String> {
    if ptr.is_null() {
        return Err(err(2, "string pointer is null"));
    }
    unsafe {
        CStr::from_ptr(ptr)
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| err(2, "string is not valid UTF-8"))
    }
}

fn write_error(err_buf: *mut c_char, err_buf_len: usize, message: &str) {
    if err_buf.is_null() || err_buf_len == 0 {
        return;
    }
    let sanitized = message.replace('\0', " ");
    let c_msg =
        CString::new(sanitized).unwrap_or_else(|_| CString::new("native faceid error").unwrap());
    let bytes = c_msg.as_bytes_with_nul();
    let n = bytes.len().min(err_buf_len);
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), err_buf as *mut u8, n);
        if n == err_buf_len {
            *err_buf.add(err_buf_len - 1) = 0;
        }
    }
}

fn err(code: i32, message: impl Into<String>) -> NativeError {
    NativeError {
        code,
        message: message.into(),
    }
}
