//go:build faceid

package faceid

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"math"
	"os"
	"os/signal"
	"time"

	"github.com/Kagami/go-face"
	"gocv.io/x/gocv"
)

var ThresholdByProfile = map[string]float32{
	"standard": 0.45,
	"hardened": 0.38,
	"paranoid": 0.32,
	"legacy":   0.45,
}

const (
	DefaultThreshold    = 0.45
	brightenAlpha       = 1.35
	brightenBeta        = 45.0
	enrollMinClean      = 5
	enrollFaceMinPct    = 0.08
	enrollEdgeMargin    = 0.06
	enrollMaxSpread     = 0.24
	verifyMaxSpread     = 0.30
	verifyMinClean      = 3
	verifyFaceMinPct    = 0.025
	verifyThresholdBump = 0.06
	verifyEdgeMargin    = 0.03
)

type Recognizer struct {
	rec       *face.Recognizer
	modelsDir string
}

type frameVariant struct {
	bytes  []byte
	width  int
	height int
}

type capturedFrame struct {
	variants []frameVariant
}

func NewRecognizer(modelsDir string) (*Recognizer, error) {
	rec, err := face.NewRecognizer(modelsDir)
	if err != nil {
		return nil, fmt.Errorf("failed to init face recognizer (models dir: %s): %w", modelsDir, err)
	}
	return &Recognizer{rec: rec, modelsDir: modelsDir}, nil
}

func (r *Recognizer) Close() {
	if r.rec != nil {
		r.rec.Close()
	}
}

func (r *Recognizer) Enroll(numFrames int) ([]float32, [][]float32, error) {
	if numFrames < 5 {
		numFrames = 12
	}

	embeddings, err := r.enrollWithPreview(numFrames)
	if err != nil {
		return nil, nil, err
	}

	embeddings = keepConsistentEmbeddings(embeddings, enrollMaxSpread)
	if len(embeddings) < enrollMinClean {
		return nil, nil, fmt.Errorf("insufficient consistent face frames: got %d, need at least %d", len(embeddings), enrollMinClean)
	}

	avg := averageEmbeddings(embeddings)
	templates := buildVerificationTemplates(embeddings)

	return avg, templates, nil
}

func (r *Recognizer) Verify(stored [][]float32, securityProfile string) (bool, float32, error) {
	return r.VerifyWithContext(context.Background(), stored, securityProfile, 24)
}

func (r *Recognizer) VerifyWithContext(ctx context.Context, stored [][]float32, securityProfile string, maxFrames int) (bool, float32, error) {
	threshold := DefaultThreshold
	if t, ok := ThresholdByProfile[securityProfile]; ok {
		threshold = float64(t)
	}
	if threshold < DefaultThreshold {
		threshold += 0.02
	}
	if len(stored) == 0 {
		return false, 0, fmt.Errorf("no stored face embeddings")
	}

	frameCh := make(chan capturedFrame, 2)
	errCh := make(chan error, 1)

	go streamFrames(ctx, frameCh, errCh)

	var bestConfidence float32
	processed := 0
	var liveEmbeddings [][]float32

	for processed < maxFrames {
		select {
		case <-ctx.Done():
			return false, bestConfidence, fmt.Errorf("verification cancelled")
		case err := <-errCh:
			if err != nil {
				return false, bestConfidence, err
			}
		case frame, ok := <-frameCh:
			if !ok {
				return false, bestConfidence, ErrNoCamera
			}
			processed++

			live, _, _, conf, ok := r.recognizeBestVariant(frame.variants, stored)
			if !ok {
				continue
			}
			dist := bestEmbeddingDistance(stored, live)

			if float64(dist) < threshold {
				return true, conf, nil
			}

			if conf > bestConfidence {
				bestConfidence = conf
			}

			liveEmbeddings = append(liveEmbeddings, live)
			stable := keepConsistentFloatEmbeddings(liveEmbeddings, verifyMaxSpread)
			if len(stable) >= verifyMinClean {
				dist = bestEmbeddingDistance(stored, averageFloatEmbeddings(stable))
				conf = 1.0 - dist
				if conf > bestConfidence {
					bestConfidence = conf
				}
				if float64(dist) < threshold+verifyThresholdBump {
					return true, conf, nil
				}
			}
		}
	}

	return false, bestConfidence, nil
}

func (r *Recognizer) enrollWithPreview(numFrames int) ([]face.Descriptor, error) {
	webcam, err := gocv.OpenVideoCapture(0)
	if err != nil {
		return nil, ErrNoCamera
	}
	defer webcam.Close()

	if !webcam.IsOpened() {
		return nil, ErrNoCamera
	}

	img := gocv.NewMat()
	defer img.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	displayCh := make(chan gocv.Mat, 1)
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		win := gocv.NewWindow("APM Face ID Enrollment (Ctrl+C to cancel)")
		defer win.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case frame, ok := <-displayCh:
				if !ok {
					return
				}
				if frame.Empty() {
					frame.Close()
					continue
				}
				win.IMShow(frame)
				win.WaitKey(1)
				frame.Close()
			}
		}
	}()

	var embeddings []face.Descriptor

	for len(embeddings) < numFrames {
		select {
		case <-ctx.Done():
			close(displayCh)
			<-doneCh
			return nil, fmt.Errorf("enrollment cancelled")
		default:
		}

		if ok := webcam.Read(&img); !ok || img.Empty() {
			continue
		}

		bright := brightenMat(img)
		variants, err := buildEnrollmentVariants(bright)
		if err != nil {
			bright.Close()
			continue
		}

		descriptor, rect, ok := r.recognizeEnrollmentVariant(variants)
		if ok {
			gocv.Rectangle(&bright, rect, color.RGBA{0, 255, 0, 0}, 2)
		}

		status := fmt.Sprintf("%s | Frames: %d/%d", enrollmentPrompt(len(embeddings), numFrames), len(embeddings), numFrames)
		if ok {
			if isUsableEnrollmentFace(bright, rect) {
				embeddings = append(embeddings, descriptor)
				status = fmt.Sprintf("%s | Captured %d/%d", enrollmentPrompt(len(embeddings), numFrames), len(embeddings), numFrames)
			} else {
				status = fmt.Sprintf("%s | Move closer and keep your face fully visible", enrollmentPrompt(len(embeddings), numFrames))
			}
		} else {
			status = fmt.Sprintf("%s | No face detected", enrollmentPrompt(len(embeddings), numFrames))
		}

		drawEnrollmentBanner(&bright, status)

		if !trySendFrame(displayCh, bright) {
			bright.Close()
		}
	}

	close(displayCh)
	<-doneCh
	return embeddings, nil
}

func streamFrames(ctx context.Context, out chan<- capturedFrame, errCh chan<- error) {
	webcam, err := gocv.OpenVideoCapture(0)
	if err != nil {
		errCh <- ErrNoCamera
		close(out)
		return
	}
	defer webcam.Close()

	if !webcam.IsOpened() {
		errCh <- ErrNoCamera
		close(out)
		return
	}

	img := gocv.NewMat()
	defer img.Close()

	for {
		select {
		case <-ctx.Done():
			close(out)
			return
		default:
		}

		if ok := webcam.Read(&img); !ok || img.Empty() {
			time.Sleep(20 * time.Millisecond)
			continue
		}

		bright := brightenMat(img)
		variants, err := buildVerificationVariants(bright)
		bright.Close()
		if err != nil {
			continue
		}

		select {
		case out <- capturedFrame{variants: variants}:
		default:
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func brightenMat(src gocv.Mat) gocv.Mat {
	gray := gocv.NewMat()
	defer gray.Close()
	gocv.CvtColor(src, &gray, gocv.ColorBGRToGray)

	mean := gray.Mean()
	brightness := mean.Val1
	alpha := brightenAlpha
	beta := brightenBeta
	gamma := 1.0

	switch {
	case brightness < 35:
		alpha = 1.75
		beta = 70
		gamma = 1.45
	case brightness < 55:
		alpha = 1.55
		beta = 55
		gamma = 1.25
	case brightness < 80:
		alpha = 1.4
		beta = 42
		gamma = 1.1
	}

	dst := gocv.NewMat()
	gocv.ConvertScaleAbs(src, &dst, alpha, beta)
	if gamma > 1.0 {
		applyGamma(&dst, gamma)
	}
	return dst
}

func trySendFrame(ch chan<- gocv.Mat, frame gocv.Mat) bool {
	select {
	case ch <- frame:
		return true
	default:
		return false
	}
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

func float32SliceToDescriptor(s []float32) face.Descriptor {
	var d face.Descriptor
	for i := 0; i < 128 && i < len(s); i++ {
		d[i] = s[i]
	}
	return d
}

func descriptorToFloat32Slice(d face.Descriptor) []float32 {
	s := make([]float32, 128)
	for i := 0; i < 128; i++ {
		s[i] = float32(d[i])
	}
	return s
}

func averageEmbeddings(embeddings []face.Descriptor) []float32 {
	avg := make([]float32, 128)
	for _, emb := range embeddings {
		for i := 0; i < 128; i++ {
			avg[i] += float32(emb[i])
		}
	}
	count := float32(len(embeddings))
	for i := range avg {
		avg[i] /= count
	}
	return avg
}

func buildVerificationTemplates(embeddings []face.Descriptor) [][]float32 {
	var templates [][]float32
	for _, emb := range embeddings {
		candidate := descriptorToFloat32Slice(emb)
		duplicate := false
		for _, existing := range templates {
			if cosineDistance(existing, candidate) <= verifyMaxSpread {
				duplicate = true
				break
			}
		}
		if !duplicate {
			templates = append(templates, candidate)
		}
	}
	if len(templates) == 0 && len(embeddings) > 0 {
		templates = append(templates, averageEmbeddings(embeddings))
	}
	return templates
}

func bestEmbeddingDistance(stored [][]float32, live []float32) float32 {
	best := float32(1.0)
	for _, candidate := range stored {
		dist := cosineDistance(candidate, live)
		if dist < best {
			best = dist
		}
	}
	return best
}

func averageFloatEmbeddings(embeddings [][]float32) []float32 {
	if len(embeddings) == 0 {
		return nil
	}
	avg := make([]float32, 128)
	for _, emb := range embeddings {
		for i := 0; i < 128 && i < len(emb); i++ {
			avg[i] += emb[i]
		}
	}
	count := float32(len(embeddings))
	for i := range avg {
		avg[i] /= count
	}
	return avg
}

func keepConsistentFloatEmbeddings(embeddings [][]float32, maxDistance float32) [][]float32 {
	if len(embeddings) <= verifyMinClean {
		return embeddings
	}

	bestIndex := -1
	bestNeighbors := -1
	for i := range embeddings {
		neighbors := 0
		for j := range embeddings {
			if cosineDistance(embeddings[i], embeddings[j]) <= maxDistance {
				neighbors++
			}
		}
		if neighbors > bestNeighbors {
			bestNeighbors = neighbors
			bestIndex = i
		}
	}
	if bestIndex == -1 {
		return nil
	}

	var filtered [][]float32
	reference := embeddings[bestIndex]
	for i := range embeddings {
		if cosineDistance(reference, embeddings[i]) <= maxDistance {
			filtered = append(filtered, embeddings[i])
		}
	}
	return filtered
}

func isUsableEnrollmentFace(frame gocv.Mat, rect image.Rectangle) bool {
	if frame.Empty() {
		return false
	}

	frameW := frame.Cols()
	frameH := frame.Rows()
	if frameW == 0 || frameH == 0 {
		return false
	}

	faceW := rect.Dx()
	faceH := rect.Dy()
	if faceW <= 0 || faceH <= 0 {
		return false
	}

	frameArea := float64(frameW * frameH)
	faceArea := float64(faceW * faceH)
	if faceArea/frameArea < enrollFaceMinPct {
		return false
	}

	marginX := int(float64(frameW) * enrollEdgeMargin)
	marginY := int(float64(frameH) * enrollEdgeMargin)

	return rect.Min.X >= marginX &&
		rect.Min.Y >= marginY &&
		rect.Max.X <= frameW-marginX &&
		rect.Max.Y <= frameH-marginY
}

func isUsableVerificationFace(rect image.Rectangle, frameW, frameH int) bool {
	if frameW == 0 || frameH == 0 {
		return true
	}

	faceArea := float64(rect.Dx() * rect.Dy())
	frameArea := float64(frameW * frameH)
	if frameArea == 0 {
		return true
	}

	marginX := int(float64(frameW) * verifyEdgeMargin)
	marginY := int(float64(frameH) * verifyEdgeMargin)
	return faceArea/frameArea >= verifyFaceMinPct &&
		rect.Min.X >= marginX &&
		rect.Min.Y >= marginY &&
		rect.Max.X <= frameW-marginX &&
		rect.Max.Y <= frameH-marginY
}

func keepConsistentEmbeddings(embeddings []face.Descriptor, maxDistance float32) []face.Descriptor {
	if len(embeddings) <= enrollMinClean {
		return embeddings
	}

	bestIndex := -1
	bestNeighbors := -1

	for i := range embeddings {
		neighbors := 0
		for j := range embeddings {
			dist := cosineDistance(
				descriptorToFloat32Slice(embeddings[i]),
				descriptorToFloat32Slice(embeddings[j]),
			)
			if dist <= maxDistance {
				neighbors++
			}
		}
		if neighbors > bestNeighbors {
			bestNeighbors = neighbors
			bestIndex = i
		}
	}

	if bestIndex == -1 {
		return nil
	}

	var filtered []face.Descriptor
	reference := descriptorToFloat32Slice(embeddings[bestIndex])
	for i := range embeddings {
		dist := cosineDistance(reference, descriptorToFloat32Slice(embeddings[i]))
		if dist <= maxDistance {
			filtered = append(filtered, embeddings[i])
		}
	}

	return filtered
}

func enrollmentPrompt(captured, total int) string {
	if total <= 0 {
		return "Look naturally at the camera"
	}
	progress := float64(captured) / float64(total)
	switch {
	case progress < 0.2:
		return "Look straight at the screen"
	case progress < 0.4:
		return "Glance slightly left"
	case progress < 0.6:
		return "Glance slightly right"
	case progress < 0.8:
		return "Lift your chin a little"
	default:
		return "Relax and look naturally anywhere on screen"
	}
}

func drawEnrollmentBanner(frame *gocv.Mat, status string) {
	if frame == nil || frame.Empty() {
		return
	}

	paddingX := 8
	paddingY := 8
	textOrigin := image.Pt(18, 34)
	textSize := gocv.GetTextSize(status, gocv.FontHersheySimplex, 0.72, 2)
	topLeft := image.Pt(10, 10)
	bottomRight := image.Pt(textOrigin.X+textSize.X+paddingX, textOrigin.Y+paddingY)
	gocv.Rectangle(frame, image.Rect(topLeft.X, topLeft.Y, bottomRight.X, bottomRight.Y), color.RGBA{245, 245, 245, 0}, -1)
	gocv.Rectangle(frame, image.Rect(topLeft.X, topLeft.Y, bottomRight.X, bottomRight.Y), color.RGBA{25, 25, 25, 0}, 1)
	gocv.PutText(frame, status, textOrigin, gocv.FontHersheySimplex, 0.72, color.RGBA{0, 0, 0, 0}, 2)
}

func applyGamma(frame *gocv.Mat, gamma float64) {
	if frame == nil || frame.Empty() || gamma <= 0 || gamma == 1.0 {
		return
	}

	lut := gocv.NewMatWithSize(1, 256, gocv.MatTypeCV8U)
	defer lut.Close()
	invGamma := 1.0 / gamma
	for i := 0; i < 256; i++ {
		value := math.Pow(float64(i)/255.0, invGamma) * 255.0
		if value < 0 {
			value = 0
		}
		if value > 255 {
			value = 255
		}
		lut.SetUCharAt(0, i, uint8(value))
	}

	adjusted := gocv.NewMat()
	defer adjusted.Close()
	gocv.LUT(*frame, lut, &adjusted)
	adjusted.CopyTo(frame)
}

func buildEnrollmentVariants(enhanced gocv.Mat) ([]frameVariant, error) {
	return buildFrameVariants(enhanced, false)
}

func buildVerificationVariants(enhanced gocv.Mat) ([]frameVariant, error) {
	return buildFrameVariants(enhanced, true)
}

func buildFrameVariants(enhanced gocv.Mat, allowUpscale bool) ([]frameVariant, error) {
	var variants []frameVariant

	addVariant := func(mat gocv.Mat) error {
		buf, err := gocv.IMEncode(gocv.JPEGFileExt, mat)
		if err != nil {
			return err
		}
		variants = append(variants, frameVariant{
			bytes:  append([]byte(nil), buf.GetBytes()...),
			width:  mat.Cols(),
			height: mat.Rows(),
		})
		buf.Close()
		return nil
	}

	if err := addVariant(enhanced); err != nil {
		return nil, err
	}

	if allowUpscale && enhanced.Cols() > 0 && enhanced.Cols() < 640 {
		upscaled := gocv.NewMat()
		targetWidth := 640
		targetHeight := int(float64(enhanced.Rows()) * (float64(targetWidth) / float64(enhanced.Cols())))
		gocv.Resize(enhanced, &upscaled, image.Pt(targetWidth, targetHeight), 0, 0, gocv.InterpolationLinear)
		if !upscaled.Empty() {
			_ = addVariant(upscaled)
		}
		upscaled.Close()
	}

	denoised := gocv.NewMat()
	if err := gocv.BilateralFilter(enhanced, &denoised, 5, 35, 35); err == nil && !denoised.Empty() {
		_ = addVariant(denoised)
	}
	denoised.Close()

	return variants, nil
}

func (r *Recognizer) recognizeEnrollmentVariant(variants []frameVariant) (face.Descriptor, image.Rectangle, bool) {
	bestArea := 0
	var bestDescriptor face.Descriptor
	var bestRect image.Rectangle

	for _, variant := range variants {
		faces, err := r.rec.Recognize(variant.bytes)
		if err != nil || len(faces) != 1 {
			continue
		}
		rect := faces[0].Rectangle
		area := rect.Dx() * rect.Dy()
		if area > bestArea {
			bestArea = area
			bestDescriptor = faces[0].Descriptor
			bestRect = rect
		}
	}

	return bestDescriptor, bestRect, bestArea > 0
}

func (r *Recognizer) recognizeBestVariant(variants []frameVariant, stored [][]float32) ([]float32, int, int, float32, bool) {
	bestDist := float32(1.0)
	var bestEmbedding []float32
	bestW := 0
	bestH := 0

	for _, variant := range variants {
		faces, err := r.rec.Recognize(variant.bytes)
		if err != nil || len(faces) != 1 {
			continue
		}
		if !isUsableVerificationFace(faces[0].Rectangle, variant.width, variant.height) {
			continue
		}
		live := descriptorToFloat32Slice(faces[0].Descriptor)
		dist := bestEmbeddingDistance(stored, live)
		if dist < bestDist {
			bestDist = dist
			bestEmbedding = live
			bestW = variant.width
			bestH = variant.height
		}
	}

	if len(bestEmbedding) == 0 {
		return nil, 0, 0, 0, false
	}
	return bestEmbedding, bestW, bestH, 1.0 - bestDist, true
}
