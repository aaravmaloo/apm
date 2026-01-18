package apm

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/api/drive/v3"
)

func (cm *GoogleDriveManager) EnsurePluginsFolder() (string, error) {

	query := fmt.Sprintf("name = 'plugins' and '%s' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false", DriveFolderID)
	list, err := cm.Service.Files.List().Q(query).Fields("files(id)").Do()
	if err != nil {
		return "", err
	}

	if len(list.Files) > 0 {
		return list.Files[0].Id, nil
	}

	dir := &drive.File{
		Name:     "plugins",
		Parents:  []string{DriveFolderID},
		MimeType: "application/vnd.google-apps.folder",
	}
	res, err := cm.Service.Files.Create(dir).Fields("id").Do()
	if err != nil {
		return "", err
	}
	return res.Id, nil
}

func (cm *GoogleDriveManager) UploadPlugin(name string, pluginPath string) error {
	pluginsFolderID, err := cm.EnsurePluginsFolder()
	if err != nil {
		return err
	}

	zipPath := filepath.Join(os.TempDir(), name+".zip")
	if err := zipFolder(pluginPath, zipPath); err != nil {
		return err
	}

	query := fmt.Sprintf("name = '%s.zip' and '%s' in parents and trashed = false", name, pluginsFolderID)
	list, err := cm.Service.Files.List().Q(query).Fields("files(id)").Do()
	if err != nil {
		return err
	}

	f, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if len(list.Files) > 0 {

		fileID := list.Files[0].Id
		_, err = cm.Service.Files.Update(fileID, &drive.File{}).Media(f).Do()
	} else {

		file := &drive.File{
			Name:    name + ".zip",
			Parents: []string{pluginsFolderID},
		}
		_, err = cm.Service.Files.Create(file).Media(f).Do()
	}
	return err
}

func (cm *GoogleDriveManager) ListMarketplacePlugins() ([]string, error) {
	pluginsFolderID, err := cm.EnsurePluginsFolder()
	if err != nil {
		return nil, err
	}

	query := fmt.Sprintf("'%s' in parents and trashed = false", pluginsFolderID)
	list, err := cm.Service.Files.List().Q(query).Fields("files(name)").Do()
	if err != nil {
		return nil, err
	}

	var names []string
	for _, f := range list.Files {
		if strings.HasSuffix(f.Name, ".zip") {
			names = append(names, strings.TrimSuffix(f.Name, ".zip"))
		}
	}
	return names, nil
}

func (cm *GoogleDriveManager) DownloadPlugin(name string, destDir string) error {
	pluginsFolderID, err := cm.EnsurePluginsFolder()
	if err != nil {
		return err
	}

	query := fmt.Sprintf("name = '%s.zip' and '%s' in parents and trashed = false", name, pluginsFolderID)
	list, err := cm.Service.Files.List().Q(query).Fields("files(id)").Do()
	if err != nil {
		return err
	}
	if len(list.Files) == 0 {
		return fmt.Errorf("plugin '%s' not found in marketplace", name)
	}
	fileID := list.Files[0].Id

	resp, err := cm.Service.Files.Get(fileID).Download()
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmpZip := filepath.Join(os.TempDir(), name+"_download.zip")
	out, err := os.Create(tmpZip)
	if err != nil {
		return err
	}
	defer func() {
		out.Close()
		os.Remove(tmpZip)
	}()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	out.Close()

	return unzip(tmpZip, destDir)
}

func zipFolder(source, target string) error {
	zipfile, err := os.Create(target)
	if err != nil {
		return err
	}
	defer zipfile.Close()

	archive := zip.NewWriter(zipfile)
	defer archive.Close()

	return filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == source {
			return nil
		}

		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}

		relPath, _ := filepath.Rel(source, path)
		header.Name = relPath

		if info.IsDir() {
			header.Name += "/"
		} else {
			header.Method = zip.Deflate
		}

		writer, err := archive.CreateHeader(header)
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(writer, file)
		return err
	})
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}
