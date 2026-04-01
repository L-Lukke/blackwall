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
	LogFile *os.File
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

func FindRepoRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return "."
	}

	candidates := []string{
		cwd,
		filepath.Dir(cwd),
	}

	for _, candidate := range candidates {
		if isRepoRoot(candidate) {
			return candidate
		}
	}

	return cwd
}

func isRepoRoot(path string) bool {
	required := []string{
		"gateway",
		"issuer",
		"devices",
		"scenarios",
	}

	for _, name := range required {
		info, err := os.Stat(filepath.Join(path, name))
		if err != nil || !info.IsDir() {
			return false
		}
	}

	return true
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
			Name:    "sensor-sim",
			WorkDir: "devices/sensor-sim",
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
				"SENSOR_URL=http://127.0.0.1:8091",
				"LOCAL_SINK_FILE=../../testdata/data/local-sink.ndjson",
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
		if existing, ok := m.services[spec.Name]; ok {
			if isManagedProcessRunning(existing) {
				continue
			}
			_ = closeManagedResources(existing)
			delete(m.services, spec.Name)
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
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}

		if err := cmd.Start(); err != nil {
			_ = logFile.Close()
			return fmt.Errorf("start %s: %w", spec.Name, err)
		}

		m.services[spec.Name] = &ManagedProcess{
			Spec:    spec,
			Cmd:     cmd,
			LogPath: logPath,
			LogFile: logFile,
		}
	}

	return nil
}

func (m *Manager) StopAll() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var firstErr error

	for name, proc := range m.services {
		if proc == nil {
			delete(m.services, name)
			continue
		}

		if err := stopManagedProcess(proc); err != nil && firstErr == nil {
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
		if proc, ok := m.services[spec.Name]; ok && isManagedProcessRunning(proc) {
			out = append(out, fmt.Sprintf("%s: running pid=%d log=%s", spec.Name, proc.Cmd.Process.Pid, proc.LogPath))
		} else {
			out = append(out, fmt.Sprintf("%s: stopped", spec.Name))
		}
	}

	return out
}

func stopManagedProcess(proc *ManagedProcess) error {
	if proc == nil || proc.Cmd == nil || proc.Cmd.Process == nil {
		return closeManagedResources(proc)
	}

	pid := proc.Cmd.Process.Pid
	done := make(chan error, 1)

	go func() {
		done <- proc.Cmd.Wait()
	}()

	_ = syscall.Kill(-pid, syscall.SIGINT)

	select {
	case <-time.After(3 * time.Second):
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		<-done
	case <-done:
	}

	return closeManagedResources(proc)
}

func closeManagedResources(proc *ManagedProcess) error {
	if proc == nil {
		return nil
	}

	if proc.LogFile != nil {
		if err := proc.LogFile.Close(); err != nil {
			return err
		}
		proc.LogFile = nil
	}

	return nil
}

func isManagedProcessRunning(proc *ManagedProcess) bool {
	if proc == nil || proc.Cmd == nil || proc.Cmd.Process == nil {
		return false
	}

	pid := proc.Cmd.Process.Pid
	err := syscall.Kill(pid, 0)
	return err == nil
}