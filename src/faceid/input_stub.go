//go:build faceid && !windows

package faceid

func inputAvailable() bool {
	return false
}
