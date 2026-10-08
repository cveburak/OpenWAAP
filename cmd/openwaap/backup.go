package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/openwaap/openwaap/internal/config"
)

type manifest struct {
	Tool      string    `json:"tool"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Files     []string  `json:"files"`
}

func runValidate(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	if !cfg.SetupPending {
		if err := checkTLSMaterial(cfg); err != nil {
			return err
		}
	}
	fmt.Printf("config OK: %s\n", configPath)
	return nil
}

func checkTLSMaterial(cfg *config.Config) error {
	check := func(label, path string) error {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("tls material missing: %s %q: %w", label, path, err)
		}
		if info.IsDir() {
			return fmt.Errorf("tls material missing: %s %q is a directory, not a file", label, path)
		}
		return nil
	}
	if err := check("server.tls_cert_file", cfg.Server.TLSCertFile); err != nil {
		return err
	}
	if err := check("server.tls_key_file", cfg.Server.TLSKeyFile); err != nil {
		return err
	}
	for _, d := range cfg.Domains {
		if d.TLS == nil || (d.TLS.CertFile == "" && d.TLS.KeyFile == "") {
			continue
		}
		if err := check(fmt.Sprintf("domain %q tls.cert_file", d.Hostname), d.TLS.CertFile); err != nil {
			return err
		}
		if err := check(fmt.Sprintf("domain %q tls.key_file", d.Hostname), d.TLS.KeyFile); err != nil {
			return err
		}
	}
	return nil
}

func runBackup(configPath, eventLogPath, outPath string) error {
	if outPath == "" {
		outPath = filepath.Join("backups", "openwaap-backup-"+time.Now().Format("20060102-150405")+".tar.gz")
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	files, err := collectBackupFiles(configPath, eventLogPath)
	if err != nil {
		return err
	}

	tmp := outPath + ".tmp"
	if err := writeArchive(tmp, configPath, files); err != nil {
		return err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("backup: finalize: %w", err)
	}
	fmt.Printf("backup written: %s (%d files)\n", outPath, len(files))
	return nil
}

func collectBackupFiles(configPath, eventLogPath string) ([]string, error) {
	roots := []string{configPath, eventLogPath, "certs"}
	seen := map[string]bool{}
	var files []string
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if !seen[root] {
				seen[root] = true
				files = append(files, root)
			}
			continue
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return nil, fmt.Errorf("backup: read %s: %w", root, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			p := filepath.Join(root, e.Name())
			if !seen[p] {
				seen[p] = true
				files = append(files, p)
			}
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("backup: nothing to back up (config %q not found?)", configPath)
	}
	return files, nil
}

func writeArchive(path, configPath string, files []string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("backup: create: %w", err)
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	m := manifest{Tool: "openwaap-backup", Version: version, CreatedAt: time.Now(), Files: files}
	mb, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: manifest: %w", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "openwaap-backup/manifest.json", Mode: 0o644, Size: int64(len(mb)), ModTime: m.CreatedAt}); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if _, err := tw.Write(mb); err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	for _, file := range files {
		if err := addToArchive(tw, file); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	return nil
}

func addToArchive(tw *tar.Writer, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("backup: stat %s: %w", path, err)
	}
	hdr := &tar.Header{
		Name:    filepath.Join("openwaap-backup", filepath.Base(path)),
		Mode:    0o600,
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	src, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("backup: open %s: %w", path, err)
	}
	defer src.Close()
	if _, err := io.Copy(tw, src); err != nil {
		return fmt.Errorf("backup: write %s: %w", path, err)
	}
	return nil
}
