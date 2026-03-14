//go:build faceid

package faceid

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gocv.io/x/gocv"
)

var ErrNoCamera = fmt.Errorf("no camera found")

func captureFrames(n int, intervalMs int) ([]string, error) {
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

	var paths []string
	tmpDir := os.TempDir()

	for i := 0; i < n; i++ {
		if ok := webcam.Read(&img); !ok || img.Empty() {
			if i == 0 {
				cleanupFrames(paths)
				return nil, ErrNoCamera
			}
			continue
		}

		ts := time.Now().UnixMilli()
		framePath := filepath.Join(tmpDir, fmt.Sprintf("apm_frame_%d_%d.jpg", ts, i))

		if ok := gocv.IMWrite(framePath, img); !ok {
			continue
		}
		paths = append(paths, framePath)

		if i < n-1 {
			time.Sleep(time.Duration(intervalMs) * time.Millisecond)
		}
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("failed to capture any frames from camera")
	}

	return paths, nil
}

func cleanupFrames(paths []string) {
	for _, p := range paths {
		os.Remove(p)
	}
}
