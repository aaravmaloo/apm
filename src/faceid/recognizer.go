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
	DefaultThreshold = 0.45
	brightenAlpha    = 1.35
	brightenBeta     = 45.0
	enrollMinClean   = 5
)

type Recognizer struct {
	rec       *face.Recognizer
	modelsDir string
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

func (r *Recognizer) Enroll(numFrames int) ([]float32, error) {
	if numFrames < 5 {
		numFrames = 10
	}

	embeddings, err := r.enrollWithPreview(numFrames)
	if err != nil {
		return nil, err
	}

	if len(embeddings) < enrollMinClean {
		return nil, fmt.Errorf("insufficient clean frames: got %d, need at least %d", len(embeddings), enrollMinClean)
	}

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

	return avg, nil
}

func (r *Recognizer) Verify(stored []float32, securityProfile string) (bool, float32, error) {
	return r.VerifyWithContext(context.Background(), stored, securityProfile, 6)
}

func (r *Recognizer) VerifyWithContext(ctx context.Context, stored []float32, securityProfile string, maxFrames int) (bool, float32, error) {
	threshold := DefaultThreshold
	if t, ok := ThresholdByProfile[securityProfile]; ok {
		threshold = float64(t)
	}

	frameCh := make(chan []byte, 2)
	errCh := make(chan error, 1)

	go streamFrames(ctx, frameCh, errCh)

	var bestConfidence float32
	processed := 0

	for processed < maxFrames {
		select {
		case <-ctx.Done():
			return false, bestConfidence, fmt.Errorf("verification cancelled")
		case err := <-errCh:
			if err != nil {
				return false, bestConfidence, err
			}
		case imgBytes, ok := <-frameCh:
			if !ok {
				return false, bestConfidence, ErrNoCamera
			}
			processed++

			faces, err := r.rec.Recognize(imgBytes)
			if err != nil || len(faces) != 1 {
				continue
			}

			dist := cosineDistance(stored, descriptorToFloat32Slice(faces[0].Descriptor))
			conf := 1.0 - dist

			if float64(dist) < threshold {
				return true, conf, nil
			}

			if conf > bestConfidence {
				bestConfidence = conf
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
		buf, err := gocv.IMEncode(gocv.JPEGFileExt, bright)
		if err != nil {
			bright.Close()
			continue
		}
		imgBytes := append([]byte(nil), buf.GetBytes()...)
		buf.Close()

		faces, err := r.rec.Recognize(imgBytes)
		if err == nil {
			for _, f := range faces {
				gocv.Rectangle(&bright, f.Rectangle, color.RGBA{0, 255, 0, 0}, 2)
			}
		}

		status := fmt.Sprintf("Frames: %d/%d", len(embeddings), numFrames)
		if err == nil && len(faces) == 1 {
			embeddings = append(embeddings, faces[0].Descriptor)
			status = fmt.Sprintf("Captured %d/%d", len(embeddings), numFrames)
		} else if err == nil && len(faces) > 1 {
			status = "Multiple faces detected"
		} else if err == nil && len(faces) == 0 {
			status = "No face detected"
		}

		gocv.PutText(
			&bright,
			status,
			image.Pt(10, 30),
			gocv.FontHersheySimplex,
			0.8,
			color.RGBA{255, 255, 255, 0},
			2,
		)

		if !trySendFrame(displayCh, bright) {
			bright.Close()
		}
	}

	close(displayCh)
	<-doneCh
	return embeddings, nil
}

func streamFrames(ctx context.Context, out chan<- []byte, errCh chan<- error) {
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
		buf, err := gocv.IMEncode(gocv.JPEGFileExt, bright)
		bright.Close()
		if err != nil {
			continue
		}
		imgBytes := append([]byte(nil), buf.GetBytes()...)
		buf.Close()

		select {
		case out <- imgBytes:
		default:
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func brightenMat(src gocv.Mat) gocv.Mat {
	dst := gocv.NewMat()
	gocv.ConvertScaleAbs(src, &dst, brightenAlpha, brightenBeta)
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
