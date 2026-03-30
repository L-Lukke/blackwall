package procmanager

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type ServiceSpec struct {
	Name    string
	WorkDir string
	Command []string
	Env     []string
}

type ManagedProcess struct {
	Spec    ServiceSpec
	Cmd     *exec.Cmd
	LogPath string
}

type Manager struct {
	root     string
	logDir   string
	mu       sync.Mutex
	services map[string]*ManagedProcess
}

func New(root string) *Manager {
	return &Manager{
		root:     root,
		logDir:   filepath.Join(root, "scenarios", ".logs"),
		services: map[string]*ManagedProcess{},
	}
}

func DefaultSpecs() []ServiceSpec {
	return []ServiceSpec{
		{
			Name:    "authz",
			WorkDir: "gateway/rust-authz",
			Command: []string{"cargo", "run"},
			Env: []string{
				"AUTHZ_SHARED_SECRET=dev-secret",
				"TRUSTED_ISSUER=did:example:issuer",
				"GATEWAY_ID=gateway-home-1",
				"POLICY_FILE=../../testdata/policies/devices.json",
				"REVOCATION_FILE=../../testdata/revocations/revoked_ids.json",
			},
		},
		{
			Name:    "lock-sim",
			WorkDir: "devices/lock-sim",
			Command: []string{"go", "run", "."},
			Env:     nil,
		},
		{
			Name:    "gateway",
			WorkDir: "gateway/go-api",
			Command: []string{"go", "run", "."},
			Env: []string{
				"AUTHZ_URL=http://127.0.0.1:8081/v1/authorize",
				"LOCK_URL=http://127.0.0.1:8090",
			},
		},
		{
			Name:    "issuer",
			WorkDir: "issuer/go-issuer",
			Command: []string{"go", "run", "."},
			Env: []string{
				"ISSUER_DID=did:example:issuer",
				"ISSUER_SHARED_SECRET=dev-secret",
				"SAVE_CREDENTIALS_DIR=../../testdata/credentials",
			},
		},
	}
}

func (m *Manager) StartAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.MkdirAll(m.logDir, 0o755); err != nil {
		return err
	}

	for _, spec := range DefaultSpecs() {
		if existing, ok := m.services[spec.Name]; ok && existing.Cmd != nil && existing.Cmd.Process != nil {
			continue
		}

		logPath := filepath.Join(m.logDir, spec.Name+".log")
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return fmt.Errorf("open log file for %s: %w", spec.Name, err)
		}

		cmd := exec.Command(spec.Command[0], spec.Command[1:]...)
		cmd.Dir = filepath.Join(m.root, spec.WorkDir)
		cmd.Env = append(os.Environ(), spec.Env...)
		cmd.Stdout = logFile
		cmd.Stderr = logFile

		if err := cmd.Start(); err != nil {
			_ = logFile.Close()
			return fmt.Errorf("start %s: %w", spec.Name, err)
		}

		m.services[spec.Name] = &ManagedProcess{
			Spec:    spec,
			Cmd:     cmd,
			LogPath: logPath,
		}

		go func(name string, c *exec.Cmd, f *os.File) {
			_ = c.Wait()
			_ = f.Close()
		}(spec.Name, cmd, logFile)
	}

	return nil
}

func (m *Manager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error

	for name, proc := range m.services {
		if proc == nil || proc.Cmd == nil || proc.Cmd.Process == nil {
			delete(m.services, name)
			continue
		}

		if err := stopProcess(proc.Cmd); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("stop %s: %w", name, err)
		}
		delete(m.services, name)
	}

	return firstErr
}

func (m *Manager) StatusLines() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []string
	for _, spec := range DefaultSpecs() {
		if proc, ok := m.services[spec.Name]; ok && proc.Cmd != nil && proc.Cmd.Process != nil {
			out = append(out, fmt.Sprintf("%s: running pid=%d log=%s", spec.Name, proc.Cmd.Process.Pid, proc.LogPath))
		} else {
			out = append(out, fmt.Sprintf("%s: stopped", spec.Name))
		}
	}
	return out
}

func stopProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	_ = cmd.Process.Signal(os.Interrupt)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(3 * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			return err
		}
		<-done
		return nil
	case err := <-done:
		if err == nil {
			return nil
		}

		if exitErr, ok := err.(*exec.ExitError); ok {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() || status.ExitStatus() == 0 {
					return nil
				}
			}
		}
		return nil
	}
}