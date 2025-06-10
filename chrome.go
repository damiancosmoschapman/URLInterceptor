package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// getChromePaths returns a list of common paths or commands for Chrome/Chromium.
func getChromePaths() []string {
	switch runtime.GOOS {
	case "windows":
		userProfile := os.Getenv("USERPROFILE")
		localAppData := os.Getenv("LOCALAPPDATA")
		programFiles := os.Getenv("ProgramFiles")
		programFilesX86 := os.Getenv("ProgramFiles(x86)")

		// Prioritize system-wide installs, then user-specific
		paths := []string{}
		if programFiles != "" {
			paths = append(paths, filepath.Join(programFiles, `Google\Chrome\Application\chrome.exe`))
		}
		if programFilesX86 != "" {
			paths = append(paths, filepath.Join(programFilesX86, `Google\Chrome\Application\chrome.exe`))
		}
		if localAppData != "" {
			paths = append(paths, filepath.Join(localAppData, `Google\Chrome\Application\chrome.exe`))
		} else if userProfile != "" { // Fallback if LOCALAPPDATA isn't set for some reason
			paths = append(paths, filepath.Join(userProfile, `AppData\Local\Google\Chrome\Application\chrome.exe`))
		}
		return paths
	case "darwin": // macOS
		return []string{
			`/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
			`/Applications/Chromium.app/Contents/MacOS/Chromium`,
		}
	case "linux":
		return []string{
			"google-chrome-stable", // Often the command for the stable channel
			"google-chrome",
			"chromium-browser",
			"chromium",
		}
	default:
		return []string{}
	}
}

// getKillInfo returns the command and arguments to kill Chrome processes.
// It also helps determine which process name to target based on the found executable.
func getKillInfo(foundExecutablePath string) (killCmdName string, killArgs []string) {
	baseName := strings.ToLower(filepath.Base(foundExecutablePath))

	switch runtime.GOOS {
	case "windows":
		// taskkill targets chrome.exe irrespective of the full path's case or specific name
		return "taskkill", []string{"/F", "/IM", "chrome.exe", "/T"}
	case "darwin": // macOS
		if strings.Contains(baseName, "chromium") {
			return "killall", []string{"Chromium"}
		}
		return "killall", []string{"Google Chrome"}
	case "linux":
		// Try to match common process names for killall
		if strings.HasPrefix(baseName, "google-chrome") {
			return "killall", []string{"chrome"} // google-chrome often runs as 'chrome'
		} else if strings.Contains(baseName, "chromium-browser") {
			return "killall", []string{"chromium-browser"}
		} else if strings.Contains(baseName, "chromium") {
			return "killall", []string{"chromium"}
		}
		return "killall", []string{"chrome"} // Default guess for Linux
	default:
		return "", []string{}
	}
}

// findChromeExecutable attempts to find the Chrome/Chromium executable.
func findChromeExecutable() (string, error) {
	pathsToTry := getChromePaths()
	if len(pathsToTry) == 0 {
		return "", fmt.Errorf("no default Chrome paths defined for OS: %s", runtime.GOOS)
	}

	for _, p := range pathsToTry {
		// If it's a command name (like on Linux), try finding it in PATH
		if runtime.GOOS == "linux" || !(strings.Contains(p, "/") || strings.Contains(p, `\`)) {
			path, err := exec.LookPath(p)
			if err == nil {
				return path, nil
			}
		} else { // If it's a full path, check if it exists
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("Chrome/Chromium executable not found in common locations for %s. Searched: %v", runtime.GOOS, pathsToTry)
}

// terminateChromeProcesses attempts to terminate all running Chrome/Chromium instances.
func terminateChromeProcesses(executablePath string) {
	killCmdName, killArgs := getKillInfo(executablePath)
	if killCmdName == "" {
		fmt.Printf("Kill command not defined for OS: %s. Skipping termination.\n", runtime.GOOS)
		return
	}

	fmt.Printf("Attempting to close existing Chrome/Chromium processes (using: %s %v)...\n", killCmdName, killArgs)
	cmd := exec.Command(killCmdName, killArgs...)
	err := cmd.Run() // .Run() waits for completion

	if err == nil {
		fmt.Println("Termination command executed successfully. Waiting a moment for processes to close...")
		time.Sleep(2 * time.Second) // Give a moment for processes to terminate
	} else {
		// On Windows, taskkill returns error code 128 if process not found.
		// On Linux/macOS, killall returns non-zero if no process found.
		// These are not critical failures for the script's main purpose if Chrome wasn't running.
		if exitErr, ok := err.(*exec.ExitError); ok {
			fmt.Printf("Termination command finished with exit code %d (this often means Chrome was not running or access was denied): %v\n", exitErr.ExitCode(), err)
		} else {
			fmt.Printf("Error executing termination command (is '%s' installed and in PATH?): %v\n", killCmdName, err)
		}
	}
}

// launchChrome attempts to launch Chrome/Chromium with the specified flags.
func launchChrome(executablePath string, flags ...string) error {
	fmt.Printf("Launching Chrome/Chromium from: '%s' with flags: %v\n", executablePath, flags)
	cmd := exec.Command(executablePath, flags...)

	// Start the process without waiting for it to complete
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to launch Chrome/Chromium: %w", err)
	}
	fmt.Printf("Chrome/Chromium launch initiated (PID: %d). The Go program will now exit; Chrome should run independently.\n", cmd.Process.Pid)
	return nil
}

func main() {
	fmt.Println("Chrome QUIC Disabler and Restarter (Go Version)")
	fmt.Println("----------------------------------------------")

	// 1. Find Chrome/Chromium executable
	chromeExecutable, err := findChromeExecutable()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("Please ensure Chrome/Chromium is installed in a common location, or that its command is in your system's PATH.")
		return
	}
	fmt.Printf("Found Chrome/Chromium executable at: %s\n", chromeExecutable)

	// 2. Terminate existing Chrome/Chromium processes
	terminateChromeProcesses(chromeExecutable)

	// 3. Launch Chrome/Chromium with QUIC disabled
	// The flag to disable the "Experimental QUIC protocol" is --disable-quic
	err = launchChrome(chromeExecutable, "--disable-quic")
	if err != nil {
		fmt.Printf("Error launching Chrome/Chromium: %v\n", err)
		return
	}

	fmt.Println("Successfully initiated Chrome/Chromium launch with QUIC disabled.")
	fmt.Println("Note: If Chrome was already running and could not be fully closed by this script, you might need to close it manually for the new instance with flags to take effect without conflicts.")
}
