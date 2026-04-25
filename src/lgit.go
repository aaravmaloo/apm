package apm

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type LGitCommit struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	Action       string    `json:"action"`
	VaultPath    string    `json:"vault_path"`
	DataHash     string    `json:"data_hash"`
	PrevHash     string    `json:"prev_hash,omitempty"`
	Hash         string    `json:"hash"`
	Signature    string    `json:"signature"`
	SnapshotFile string    `json:"snapshot_file"`
}

func getLGitFile() string {
	apmDir, _ := getAPMConfigDir()
	return filepath.Join(apmDir, "lgit.jsonl")
}

func getLGitSnapshotDir() string {
	apmDir, _ := getAPMConfigDir()
	return filepath.Join(apmDir, "lgit_snapshots")
}

func getLGitSigningKey() ([]byte, error) {
	apmDir, err := getAPMConfigDir()
	if err != nil {
		return nil, err
	}
	return loadOrCreateSigningKey(filepath.Join(apmDir, "lgit_signing.key"))
}

func GetLGitCommits(limit int) ([]LGitCommit, error) {
	path := getLGitFile()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return []LGitCommit{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var commits []LGitCommit
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var c LGitCommit
		if err := json.Unmarshal([]byte(line), &c); err == nil {
			commits = append(commits, c)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if limit > 0 && len(commits) > limit {
		return commits[len(commits)-limit:], nil
	}
	return commits, nil
}

func GetLGitHead() (*LGitCommit, error) {
	commits, err := GetLGitCommits(1)
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, nil
	}
	head := commits[len(commits)-1]
	return &head, nil
}

func FindLGitCommitByPrefix(prefix string) (*LGitCommit, int, error) {
	commits, err := GetLGitCommits(0)
	if err != nil {
		return nil, -1, err
	}
	if len(commits) == 0 {
		return nil, -1, nil
	}
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || strings.EqualFold(prefix, "head") {
		last := commits[len(commits)-1]
		return &last, len(commits) - 1, nil
	}

	match := -1
	for i := range commits {
		if strings.HasPrefix(commits[i].ID, prefix) {
			if match != -1 {
				return nil, -1, fmt.Errorf("ambiguous commit prefix '%s'", prefix)
			}
			match = i
		}
	}
	if match == -1 {
		return nil, -1, nil
	}
	found := commits[match]
	return &found, match, nil
}

func VerifyLGitCommits(commits []LGitCommit) []bool {
	out := make([]bool, len(commits))
	key, err := getLGitSigningKey()
	if err != nil {
		return out
	}
	prevHash := ""
	for i, c := range commits {
		ok := c.Hash != "" && c.Signature != ""
		if ok {
			content := fmt.Sprintf("%s:%d:%s:%s:%s:%s:%s", c.ID, c.Timestamp.UnixNano(), c.Action, c.VaultPath, c.DataHash, c.PrevHash, c.SnapshotFile)
			sum := sha256.Sum256([]byte(content))
			expectedHash := hex.EncodeToString(sum[:])
			if !hmac.Equal([]byte(expectedHash), []byte(c.Hash)) {
				ok = false
			}
		}
		if ok {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(c.Hash))
			expectedSig := hex.EncodeToString(mac.Sum(nil))
			if !hmac.Equal([]byte(expectedSig), []byte(c.Signature)) {
				ok = false
			}
		}
		if ok && c.PrevHash != "" && c.PrevHash != prevHash {
			ok = false
		}
		out[i] = ok
		prevHash = c.Hash
	}
	return out
}

func VerifyLGitHistory() (int, int, error) {
	commits, err := GetLGitCommits(0)
	if err != nil {
		return 0, 0, err
	}
	flags := VerifyLGitCommits(commits)
	ok := 0
	for _, v := range flags {
		if v {
			ok++
		}
	}
	return ok, len(commits), nil
}

func RecordLGitCommit(vaultPath string, data []byte, action string) error {
	if len(data) == 0 {
		return nil
	}

	if action == "" {
		action = "SAVE"
	}

	all, err := GetLGitCommits(0)
	if err != nil {
		return err
	}

	dataSum := sha256.Sum256(data)
	dataHash := hex.EncodeToString(dataSum[:])

	prevHash := ""
	if n := len(all); n > 0 {
		prev := all[n-1]
		prevHash = prev.Hash
		if prev.DataHash == dataHash && prev.VaultPath == vaultPath && action == "SAVE" {
			return nil
		}
	}

	if err := os.MkdirAll(getLGitSnapshotDir(), 0700); err != nil {
		return err
	}

	now := time.Now().UTC()
	id := fmt.Sprintf("%d-%s", now.UnixNano(), dataHash[:12])
	snapshotFile := filepath.Join(getLGitSnapshotDir(), id+".vault")
	if err := os.WriteFile(snapshotFile, data, 0600); err != nil {
		return err
	}

	commit := LGitCommit{
		ID:           id,
		Timestamp:    now,
		Action:       action,
		VaultPath:    vaultPath,
		DataHash:     dataHash,
		PrevHash:     prevHash,
		SnapshotFile: snapshotFile,
	}

	content := fmt.Sprintf("%s:%d:%s:%s:%s:%s:%s", commit.ID, commit.Timestamp.UnixNano(), commit.Action, commit.VaultPath, commit.DataHash, commit.PrevHash, commit.SnapshotFile)
	sum := sha256.Sum256([]byte(content))
	commit.Hash = hex.EncodeToString(sum[:])

	key, err := getLGitSigningKey()
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(commit.Hash))
	commit.Signature = hex.EncodeToString(mac.Sum(nil))

	f, err := os.OpenFile(getLGitFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	line, _ := json.Marshal(commit)
	_, err = f.WriteString(string(line) + "\n")
	return err
}

func CheckoutLGit(vaultPath string, commitPrefix string) error {
	commit, _, err := FindLGitCommitByPrefix(commitPrefix)
	if err != nil {
		return err
	}
	if commit == nil {
		return fmt.Errorf("commit '%s' not found", commitPrefix)
	}

	data, err := os.ReadFile(commit.SnapshotFile)
	if err != nil {
		return err
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		return err
	}
	return RecordLGitCommit(vaultPath, data, "CHECKOUT")
}

func SquashLGitHistory(vaultPath string, keep int) error {
	if keep < 1 {
		keep = 1
	}
	commits, err := GetLGitCommits(0)
	if err != nil {
		return err
	}
	if len(commits) <= keep {
		return nil
	}

	keepFrom := len(commits) - keep
	for _, c := range commits[:keepFrom] {
		if c.SnapshotFile != "" {
			_ = os.Remove(c.SnapshotFile)
		}
	}

	kept := commits[keepFrom:]
	if err := rewriteLGitChain(kept); err != nil {
		return err
	}

	latest, err := os.ReadFile(kept[len(kept)-1].SnapshotFile)
	if err != nil {
		return err
	}
	return RecordLGitCommit(vaultPath, latest, "SQUASH")
}

func UndoLGit(vaultPath string) error {
	commits, err := GetLGitCommits(0)
	if err != nil {
		return err
	}
	if len(commits) < 2 {
		return fmt.Errorf("not enough lgit history to undo")
	}

	target := commits[len(commits)-2]
	data, err := os.ReadFile(target.SnapshotFile)
	if err != nil {
		return err
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		return err
	}
	return RecordLGitCommit(vaultPath, data, "UNDO")
}

func LGitStatus(vaultPath string) (bool, string, string, bool, error) {
	head, err := GetLGitHead()
	if err != nil {
		return false, "", "", false, err
	}
	if head == nil {
		return false, "", "", false, nil
	}

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		if os.IsNotExist(err) {
			return true, head.ID, head.DataHash, false, nil
		}
		return true, head.ID, head.DataHash, false, err
	}
	sum := sha256.Sum256(data)
	currentHash := hex.EncodeToString(sum[:])
	return true, head.ID, head.DataHash, currentHash == head.DataHash, nil
}

func PruneLGitSnapshots() (int, int, error) {
	commits, err := GetLGitCommits(0)
	if err != nil {
		return 0, 0, err
	}
	keep := make(map[string]struct{}, len(commits))
	for _, c := range commits {
		if c.SnapshotFile != "" {
			keep[c.SnapshotFile] = struct{}{}
		}
	}

	files, err := os.ReadDir(getLGitSnapshotDir())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, err
	}

	removed := 0
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		path := filepath.Join(getLGitSnapshotDir(), file.Name())
		if _, ok := keep[path]; ok {
			continue
		}
		if err := os.Remove(path); err == nil {
			removed++
		}
	}

	return removed, len(files) - removed, nil
}

func rewriteLGitChain(commits []LGitCommit) error {
	if len(commits) == 0 {
		return os.WriteFile(getLGitFile(), nil, 0600)
	}

	key, err := getLGitSigningKey()
	if err != nil {
		return err
	}

	prevHash := ""
	for i := range commits {
		commits[i].PrevHash = prevHash
		content := fmt.Sprintf("%s:%d:%s:%s:%s:%s:%s", commits[i].ID, commits[i].Timestamp.UnixNano(), commits[i].Action, commits[i].VaultPath, commits[i].DataHash, commits[i].PrevHash, commits[i].SnapshotFile)
		sum := sha256.Sum256([]byte(content))
		commits[i].Hash = hex.EncodeToString(sum[:])

		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(commits[i].Hash))
		commits[i].Signature = hex.EncodeToString(mac.Sum(nil))
		prevHash = commits[i].Hash
	}

	var b strings.Builder
	for _, c := range commits {
		line, _ := json.Marshal(c)
		b.Write(line)
		b.WriteByte('\n')
	}
	return os.WriteFile(getLGitFile(), []byte(b.String()), 0600)
}
