//go:build faceid

package faceid

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type modelSpec struct {
	Name string
	URL  string
}

var requiredModels = []modelSpec{
	{
		Name: "shape_predictor_5_face_landmarks.dat",
		URL:  "https://github.com/Kagami/go-face-testdata/raw/master/models/shape_predictor_5_face_landmarks.dat",
	},
	{
		Name: "dlib_face_recognition_resnet_model_v1.dat",
		URL:  "https://github.com/Kagami/go-face-testdata/raw/master/models/dlib_face_recognition_resnet_model_v1.dat",
	},
	{
		Name: "mmod_human_face_detector.dat",
		URL:  "https://github.com/Kagami/go-face-testdata/raw/master/models/mmod_human_face_detector.dat",
	},
}

func EnsureModels(modelsDir string) error {
	if modelsDir == "" {
		return fmt.Errorf("models directory not set")
	}
	if err := os.MkdirAll(modelsDir, 0700); err != nil {
		return fmt.Errorf("failed to create models dir: %w", err)
	}

	for _, m := range requiredModels {
		dst := filepath.Join(modelsDir, m.Name)
		if fi, err := os.Stat(dst); err == nil && fi.Size() > 0 {
			continue
		}
		if err := downloadFile(dst, m.URL); err != nil {
			return fmt.Errorf("failed to download %s: %w", m.Name, err)
		}
	}

	return nil
}

func downloadFile(dstPath, url string) error {
	tmpPath := dstPath + ".tmp"
	_ = os.Remove(tmpPath)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "apm-faceid/1.0")

	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}

	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}

	if err := os.Rename(tmpPath, dstPath); err != nil {
		return err
	}
	return nil
}
