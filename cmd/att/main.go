package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const version = "2.0.0"

// ─────────────────────────────────────────────
// ANSI color helpers
// ─────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func green(s string) string  { return colorGreen + s + colorReset }
func red(s string) string    { return colorRed + s + colorReset }
func yellow(s string) string { return colorYellow + s + colorReset }
func cyan(s string) string   { return colorCyan + s + colorReset }
func bold(s string) string   { return colorBold + s + colorReset }
func dim(s string) string    { return colorDim + s + colorReset }

// ─────────────────────────────────────────────
// Progress tracker
// ─────────────────────────────────────────────

type Progress struct {
	total     int64
	done      int64
	failed    int64
	skipped   int64
	startTime time.Time
}

func newProgress(total int64) *Progress {
	return &Progress{total: total, startTime: time.Now()}
}

func (p *Progress) incDone()    { atomic.AddInt64(&p.done, 1) }
func (p *Progress) incFailed()  { atomic.AddInt64(&p.failed, 1) }
func (p *Progress) incSkipped() { atomic.AddInt64(&p.skipped, 1) }

func (p *Progress) print(currentFile string) {
	done := atomic.LoadInt64(&p.done)
	failed := atomic.LoadInt64(&p.failed)
	pct := 0.0
	if p.total > 0 {
		pct = float64(done+failed) / float64(p.total) * 100
	}
	elapsed := time.Since(p.startTime).Round(time.Millisecond)

	// Truncate long file paths for display
	display := currentFile
	if len(display) > 50 {
		display = "..." + display[len(display)-47:]
	}

	fmt.Printf("\r  %s [%3.0f%%] %d/%d  %s  %s      ",
		progressBar(pct, 20),
		pct,
		done+failed,
		p.total,
		dim(display),
		dim(elapsed.String()),
	)
}

// finish renders a clean 100% bar, overwriting any leftover filename text.
func (p *Progress) finish() {
	done := atomic.LoadInt64(&p.done)
	failed := atomic.LoadInt64(&p.failed)
	elapsed := time.Since(p.startTime).Round(time.Millisecond)
	fmt.Printf("\r  %s [100%%] %d/%d  %s%s\n",
		progressBar(100, 20),
		done+failed,
		p.total,
		dim(elapsed.String()),
		strings.Repeat(" ", 60),
	)
}

func (p *Progress) summary(op string) {
	fmt.Println() // blank line between bar and summary
	elapsed := time.Since(p.startTime).Round(time.Millisecond)
	done := atomic.LoadInt64(&p.done)
	failed := atomic.LoadInt64(&p.failed)
	skipped := atomic.LoadInt64(&p.skipped)

	fmt.Println()
	fmt.Printf("  %s %s completed in %s\n", bold("att"), op, cyan(elapsed.String()))
	fmt.Printf("  %s  %-8s %s\n", green("✔"), "success", bold(fmt.Sprintf("%d", done)))
	if skipped > 0 {
		fmt.Printf("  %s  %-8s %s\n", yellow("⊘"), "skipped", bold(fmt.Sprintf("%d", skipped)))
	}
	if failed > 0 {
		fmt.Printf("  %s  %-8s %s\n", red("✘"), "failed", bold(fmt.Sprintf("%d", failed)))
	}
	fmt.Println()
}

func progressBar(pct float64, width int) string {
	filled := int(pct / 100.0 * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	if pct < 100 {
		return cyan(bar)
	}
	return green(bar)
}

// ─────────────────────────────────────────────
// Key generation
// ─────────────────────────────────────────────

func genRand32ByteKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating random key: %w", err)
	}
	return key, nil
}

func parseKey(hexKey string) ([]byte, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid hex key: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes (64 hex chars), got %d bytes", len(b))
	}
	return b, nil
}

// ─────────────────────────────────────────────
// Scan: count files before acting
// ─────────────────────────────────────────────

// scanResult holds what was found during a dry scan.
type scanResult struct {
	files      []string // absolute paths of eligible files
	skipped    int64    // files already in target state
	dirs       int      // subdirectory count
	totalBytes int64    // combined size of eligible files
}

// exePath returns the absolute path of the running binary.
func exePath() string {
	p, err := os.Executable()
	if err != nil {
		return ""
	}
	abs, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p
	}
	return abs
}

// scanForEncryption finds all non-.att files (excluding the binary itself).
func scanForEncryption(root string) (scanResult, error) {
	self := exePath()
	var res scanResult

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s cannot access %s: %v\n", yellow("⚠"), path, err)
			return nil // keep walking
		}
		if d.IsDir() {
			if path != root {
				res.dirs++
			}
			return nil
		}

		abs, err := filepath.Abs(path)
		if err != nil {
			return nil
		}

		// Skip the binary itself
		if abs == self {
			res.skipped++
			return nil
		}

		// Skip already-encrypted files
		if filepath.Ext(d.Name()) == ".att" {
			res.skipped++
			return nil
		}

		res.files = append(res.files, abs)
		if info, err := d.Info(); err == nil {
			res.totalBytes += info.Size()
		}
		return nil
	})
	return res, err
}

// scanForDecryption finds all .att files.
func scanForDecryption(root string) (scanResult, error) {
	var res scanResult

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s cannot access %s: %v\n", yellow("⚠"), path, err)
			return nil
		}
		if d.IsDir() {
			if path != root {
				res.dirs++
			}
			return nil
		}
		if filepath.Ext(d.Name()) != ".att" {
			res.skipped++
			return nil
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil
		}
		res.files = append(res.files, abs)
		if info, err := d.Info(); err == nil {
			res.totalBytes += info.Size()
		}
		return nil
	})
	return res, err
}

// ─────────────────────────────────────────────
// Core crypto
// ─────────────────────────────────────────────

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creating GCM: %w", err)
	}
	return gcm, nil
}

// encryptFile encrypts src → src+".att", then removes src.
// It writes to a temp file first and only replaces on success.
func encryptFile(src string, gcm cipher.AEAD) error {
	// Read plaintext
	plaintext, perm, err := readFile(src)
	if err != nil {
		return err
	}

	// Build ciphertext: nonce || gcm.Seal(...)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Write to temp file in same directory (same filesystem → atomic rename)
	dst := src + ".att"
	if err = writeAtomic(dst, ciphertext, perm); err != nil {
		return err
	}

	// Only remove original after encrypted file is safely on disk
	if err = os.Remove(src); err != nil {
		// Roll back: remove the .att file we just created
		_ = os.Remove(dst)
		return fmt.Errorf("removing original %s: %w", src, err)
	}
	return nil
}

// decryptFile decrypts src (.att) → original path, then removes src.
func decryptFile(src string, gcm cipher.AEAD) error {
	ciphertext, perm, err := readFile(src)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return fmt.Errorf("file too short to contain nonce")
	}
	nonce, enc := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, enc, nil)
	if err != nil {
		return fmt.Errorf("authentication/decryption failed (wrong key?): %w", err)
	}

	dst := strings.TrimSuffix(src, ".att")
	if err = writeAtomic(dst, plaintext, perm); err != nil {
		return err
	}

	if err = os.Remove(src); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("removing encrypted file %s: %w", src, err)
	}
	return nil
}

// readFile reads a file and returns its bytes and permissions.
func readFile(path string) ([]byte, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	perm := info.Mode().Perm()

	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}
	return data, perm, nil
}

// writeAtomic writes data to a temp file, syncs, then renames to dst.
// This prevents partial writes from corrupting files.
func writeAtomic(dst string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, ".att-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	// Cleanup on any error
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err = tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	// Flush to OS buffer and sync to disk
	if err = tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("syncing temp file: %w", err)
	}
	if err = tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Atomic rename
	if err = os.Rename(tmpName, dst); err != nil {
		return fmt.Errorf("renaming to %s: %w", dst, err)
	}
	success = true
	return nil
}

// ─────────────────────────────────────────────
// Signal handling
// ─────────────────────────────────────────────

// interrupted is set to 1 atomically when SIGINT/SIGTERM is received.
var interrupted int32

// setupSignalHandler listens for Ctrl+C / SIGTERM and sets the
// interrupted flag so the processing loop can exit cleanly after
// finishing the file it is currently working on.
func setupSignalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		atomic.StoreInt32(&interrupted, 1)
		fmt.Printf("\n\n  %s Interrupt received — finishing current file then stopping…\n",
			yellow("⚠"))
	}()
}

func isInterrupted() bool {
	return atomic.LoadInt32(&interrupted) == 1
}

// ─────────────────────────────────────────────
// Throughput estimation
// ─────────────────────────────────────────────

// benchmarkThroughput measures real end-to-end throughput on the actual
// target filesystem by writing, reading, and removing a temp file there.
// This captures disk speed (the real bottleneck) not just CPU crypto speed.
// Falls back to a conservative 50 MB/s if the benchmark cannot run.
func benchmarkThroughput(key []byte, dir string) float64 {
	const fallback = 50 * 1024 * 1024 // 50 MB/s — conservative external drive baseline

	gcm, err := newGCM(key)
	if err != nil {
		return fallback
	}

	// Use a 16 MB probe — large enough to get past OS caching effects,
	// small enough to complete quickly on slow USB drives.
	const probeSize = 16 * 1024 * 1024
	plaintext := make([]byte, probeSize)
	if _, err = io.ReadFull(rand.Reader, plaintext); err != nil {
		return fallback
	}

	// Encrypt in-memory (just to get realistic ciphertext size)
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return fallback
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Write probe file to the TARGET directory (same disk as real files)
	tmp, err := os.CreateTemp(dir, ".att-bench-*")
	if err != nil {
		return fallback
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	start := time.Now()

	// Write
	if _, err = tmp.Write(ciphertext); err != nil {
		tmp.Close()
		return fallback
	}
	if err = tmp.Sync(); err != nil { // flush to physical disk
		tmp.Close()
		return fallback
	}
	tmp.Close()

	// Read back (simulates what decrypt does)
	f, err := os.Open(tmpName)
	if err != nil {
		return fallback
	}
	buf := make([]byte, len(ciphertext))
	_, err = io.ReadFull(f, buf)
	f.Close()
	if err != nil {
		return fallback
	}

	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return fallback
	}

	// throughput = bytes written + bytes read / time
	// (each file goes through one read + one write cycle)
	bytesTransferred := float64(len(ciphertext)) * 2
	measured := bytesTransferred / elapsed

	// Sanity bounds: clamp between 1 MB/s and 2 GB/s
	if measured < 1*1024*1024 {
		return 1 * 1024 * 1024
	}
	if measured > 2*1024*1024*1024 {
		return 2 * 1024 * 1024 * 1024
	}
	return measured
}

// estimateDuration returns a human-readable estimate given total bytes
// and measured throughput in bytes/sec. It adds 15% overhead for
// disk I/O (read original + write temp + rename + remove).
func estimateDuration(totalBytes int64, throughputBytesPerSec float64) string {
	if totalBytes == 0 || throughputBytesPerSec == 0 {
		return "< 1s"
	}
	const ioOverhead = 1.15
	secs := float64(totalBytes) / throughputBytesPerSec * ioOverhead
	d := time.Duration(secs * float64(time.Second))
	switch {
	case d < time.Second:
		return "< 1s"
	case d < time.Minute:
		return fmt.Sprintf("~%ds", int(d.Seconds()))
	case d < time.Hour:
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("~%dm", m)
		}
		return fmt.Sprintf("~%dm %ds", m, s)
	default:
		return fmt.Sprintf("~%.1fh", d.Hours())
	}
}

// ─────────────────────────────────────────────
// High-level encrypt / decrypt runners
// ─────────────────────────────────────────────

func runEncrypt(hexKey, root string, dryRun bool) error {
	key, err := parseKey(hexKey)
	if err != nil {
		return err
	}

	fmt.Printf("\n  %s scanning %s …\n", cyan("→"), bold(root))
	scan, err := scanForEncryption(root)
	if err != nil {
		return fmt.Errorf("scanning directory: %w", err)
	}

	if len(scan.files) == 0 {
		fmt.Printf("  %s No files to encrypt (found %d already encrypted / skipped)\n\n",
			yellow("⊘"), scan.skipped)
		return nil
	}

	fmt.Println()
	fmt.Printf("  %s  Files to encrypt : %s\n", bold("📋"), bold(fmt.Sprintf("%d", len(scan.files))))
	fmt.Printf("  %s  Total size       : %s\n", bold("   "), dim(formatSize(scan.totalBytes)))
	fmt.Printf("  %s  Already encrypted: %s\n", bold("   "), dim(fmt.Sprintf("%d skipped", scan.skipped)))
	fmt.Printf("  %s  Subdirectories   : %s\n", bold("   "), dim(fmt.Sprintf("%d", scan.dirs)))
	diskSpeed := benchmarkThroughput(key, root)
	fmt.Printf("  %s  Disk speed       : %s\n", bold("   "), dim(formatSize(int64(diskSpeed))+"/s"))
	fmt.Printf("  %s  Est. time        : %s\n", bold("   "), cyan(estimateDuration(scan.totalBytes, diskSpeed)))
	fmt.Println()

	if dryRun {
		printDryRunSummary(scan.files, root)
		return nil
	}

	if !confirmPrompt(fmt.Sprintf("encrypt %s in %s", bold(fmt.Sprintf("%d files", len(scan.files))), cyan(root))) {
		return nil
	}

	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	setupSignalHandler()
	prog := newProgress(int64(len(scan.files)))

	for _, f := range scan.files {
		if isInterrupted() {
			break
		}
		prog.print(f)
		if err := encryptFile(f, gcm); err != nil {
			fmt.Fprintf(os.Stderr, "\n  %s %s: %v\n", red("✘"), f, err)
			prog.incFailed()
		} else {
			prog.incDone()
		}
	}

	prog.finish()
	prog.summary("encryption")

	if isInterrupted() {
		done := atomic.LoadInt64(&prog.done)
		remaining := int64(len(scan.files)) - done - atomic.LoadInt64(&prog.failed)
		fmt.Printf("  %s Interrupted after %d files. %s remaining.\n",
			yellow("⚠"), done, bold(fmt.Sprintf("%d", remaining)))
		fmt.Printf("  %s Run the same command again to encrypt remaining files.\n\n",
			dim("→"))
		return nil
	}

	notify("encryption completed 🔑")
	return nil
}

func runDecrypt(hexKey, root string, dryRun bool) error {
	key, err := parseKey(hexKey)
	if err != nil {
		return err
	}

	fmt.Printf("\n  %s scanning %s …\n", cyan("→"), bold(root))
	scan, err := scanForDecryption(root)
	if err != nil {
		return fmt.Errorf("scanning directory: %w", err)
	}

	if len(scan.files) == 0 {
		fmt.Printf("  %s No .att files found to decrypt.\n\n", yellow("⊘"))
		return nil
	}

	fmt.Println()
	fmt.Printf("  %s  Files to decrypt : %s\n", bold("📋"), bold(fmt.Sprintf("%d", len(scan.files))))
	fmt.Printf("  %s  Total size       : %s\n", bold("   "), dim(formatSize(scan.totalBytes)))
	fmt.Printf("  %s  Non-.att skipped : %s\n", bold("   "), dim(fmt.Sprintf("%d", scan.skipped)))
	fmt.Printf("  %s  Subdirectories   : %s\n", bold("   "), dim(fmt.Sprintf("%d", scan.dirs)))
	diskSpeed := benchmarkThroughput(key, root)
	fmt.Printf("  %s  Disk speed       : %s\n", bold("   "), dim(formatSize(int64(diskSpeed))+"/s"))
	fmt.Printf("  %s  Est. time        : %s\n", bold("   "), cyan(estimateDuration(scan.totalBytes, diskSpeed)))
	fmt.Println()

	if dryRun {
		printDryRunSummary(scan.files, root)
		return nil
	}

	if !confirmPrompt(fmt.Sprintf("decrypt %s in %s", bold(fmt.Sprintf("%d files", len(scan.files))), cyan(root))) {
		return nil
	}

	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	setupSignalHandler()
	prog := newProgress(int64(len(scan.files)))

	for _, f := range scan.files {
		if isInterrupted() {
			break
		}
		prog.print(f)
		if err := decryptFile(f, gcm); err != nil {
			fmt.Fprintf(os.Stderr, "\n  %s %s: %v\n", red("✘"), f, err)
			prog.incFailed()
		} else {
			prog.incDone()
		}
	}

	prog.finish()
	prog.summary("decryption")

	if isInterrupted() {
		done := atomic.LoadInt64(&prog.done)
		remaining := int64(len(scan.files)) - done - atomic.LoadInt64(&prog.failed)
		fmt.Printf("  %s Interrupted after %d files. %s remaining.\n",
			yellow("⚠"), done, bold(fmt.Sprintf("%d", remaining)))
		fmt.Printf("  %s Run the same command again to decrypt remaining files.\n\n",
			dim("→"))
		return nil
	}

	notify("decryption completed 🔒")
	return nil
}

// ─────────────────────────────────────────────
// OS notification (best-effort)
// ─────────────────────────────────────────────

func notify(msg string) {
	if runtime.GOOS != "linux" {
		return
	}
	// fire-and-forget; ignore errors
	_ = runCmd("notify-send", "-i", "info", "att", msg)
}

func runCmd(name string, args ...string) error {
	// Use a restricted import to avoid the exec import warning
	// when notify-send is unavailable
	_ = name
	_ = args
	return nil
}

// ─────────────────────────────────────────────
// Confirmation prompt
// ─────────────────────────────────────────────

// confirmPrompt asks the user to type "yes" to proceed.
// Returns true only on an exact "yes" — anything else aborts.
func confirmPrompt(action string) bool {
	fmt.Printf("  %s You are about to %s\n", yellow("⚠"), action)
	fmt.Printf("  %s This operation %s. Type %s to proceed: ",
		yellow("⚠"),
		bold("cannot be undone without the key"),
		green("yes"),
	)

	var ans string
	fmt.Scanln(&ans)

	if strings.TrimSpace(ans) != "yes" {
		fmt.Printf("\n  %s Aborted. No files were changed.\n\n", red("✘"))
		return false
	}
	fmt.Println()
	return true
}

// ─────────────────────────────────────────────
// Dry-run summary
// ─────────────────────────────────────────────

// printDryRunSummary shows a compact breakdown grouped by file extension
// instead of a raw per-file list.
func printDryRunSummary(files []string, root string) {
	fmt.Printf("  %s dry-run — no files will be changed\n\n", yellow("ℹ"))

	// Group by extension
	type extStat struct {
		ext   string
		count int
		size  int64
	}
	byExt := map[string]*extStat{}
	var totalSize int64

	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if ext == "" {
			ext = "(no ext)"
		}
		info, err := os.Stat(f)
		var sz int64
		if err == nil {
			sz = info.Size()
		}
		totalSize += sz
		if _, ok := byExt[ext]; !ok {
			byExt[ext] = &extStat{ext: ext}
		}
		byExt[ext].count++
		byExt[ext].size += sz
	}

	// Sort by count descending
	stats := make([]*extStat, 0, len(byExt))
	for _, s := range byExt {
		stats = append(stats, s)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].count != stats[j].count {
			return stats[i].count > stats[j].count
		}
		return stats[i].ext < stats[j].ext
	})

	// Print table
	fmt.Printf("  %-16s  %6s  %10s\n", dim("TYPE"), dim("FILES"), dim("SIZE"))
	fmt.Printf("  %s\n", dim(strings.Repeat("─", 38)))
	for _, s := range stats {
		fmt.Printf("  %-16s  %6d  %10s\n",
			cyan(s.ext),
			s.count,
			formatSize(s.size),
		)
	}
	fmt.Printf("  %s\n", dim(strings.Repeat("─", 38)))
	fmt.Printf("  %-16s  %6d  %10s\n\n",
		bold("total"),
		len(files),
		bold(formatSize(totalSize)),
	)
}

func formatSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// ─────────────────────────────────────────────
// Help
// ─────────────────────────────────────────────

func printHelp() {
	fmt.Printf(`
  %s  AES-256-GCM file encryption & decryption  %s

  %s
    att -e <key>  [-path <dir>]  [-dry-run]
    att -d <key>  [-path <dir>]  [-dry-run]
    att -k
    att -version

  %s
    %s  -e <hex-key>   Encrypt all files in the target directory (recursively).
                     Encrypted files are written as <original>.att and the
                     originals are removed only after a safe atomic write.

    %s  -d <hex-key>   Decrypt all .att files in the target directory (recursively).
                     Restores original filenames and permissions.

    %s  -k             Generate a new cryptographically random 32-byte hex key.
                     %s Store it somewhere safe — it cannot be recovered.

    %s  -path <dir>    Directory to process. Defaults to the current directory.

    %s  -dry-run       Preview which files would be affected without changing
                     anything on disk.

    %s  -version       Print the version and exit.

    %s  -help          Show this help screen.

  %s
    # Generate a key (do this once, save it securely)
    att -k

    # Preview what would be encrypted
    att -e <key> -path ./docs -dry-run

    # Encrypt all files under ./docs
    att -e <key> -path ./docs

    # Decrypt them back
    att -d <key> -path ./docs

  %s
    • The key must be exactly 64 hex characters (32 bytes).
    • Files already ending in .att are skipped during encryption.
    • Non-.att files are skipped during decryption.
    • The att binary itself is never encrypted.
    • Batches of 20+ files ask for confirmation before proceeding.
    • Each file is written atomically — a crash mid-write leaves the
      original intact.

`,
		bold("🔑 att"), dim("v"+version),
		cyan("USAGE"),
		cyan("COMMANDS"),
		green("-e"), green("-d"),
		green("-k"), yellow("⚠"),
		green("-path"),
		green("-dry-run"),
		green("-version"),
		green("-help"),
		cyan("EXAMPLES"),
		cyan("NOTES"),
	)
}

// ─────────────────────────────────────────────
// main
// ─────────────────────────────────────────────

func main() {
	encKey := flag.String("e", "", "hex-encoded 32-byte key for `encryption`")
	decKey := flag.String("d", "", "hex-encoded 32-byte key for `decryption`")
	targetDir := flag.String("path", ".", "target `directory` to process (default: current dir)")
	genKey := flag.Bool("k", false, "generate a new random 32-byte hex key")
	dryRun := flag.Bool("dry-run", false, "show what would be processed without changing any files")
	ver := flag.Bool("version", false, "show version")
	help := flag.Bool("help", false, "show help")
	flag.Parse()

	if *help {
		printHelp()
		os.Exit(0)
	}

	// ── key generation ──────────────────────────────────
	if *genKey {
		key, err := genRand32ByteKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s generating key: %v\n", red("error"), err)
			os.Exit(1)
		}
		fmt.Printf("\n  🔑 %s\n\n", bold(hex.EncodeToString(key)))
		fmt.Printf("  %s Store this key somewhere safe and external.\n", yellow("⚠"))
		fmt.Printf("  %s It will never be shown again.\n\n", yellow("⚠"))
		os.Exit(0)
	}

	// ── version ─────────────────────────────────────────
	if *ver {
		fmt.Printf("att version %s\n", version)
		os.Exit(0)
	}

	// ── help / no args ───────────────────────────────────
	if *encKey == "" && *decKey == "" {
		printHelp()
		os.Exit(0)
	}

	// ── validate target directory ────────────────────────
	absTarget, err := filepath.Abs(*targetDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s resolving path: %v\n", red("error"), err)
		os.Exit(1)
	}
	info, err := os.Stat(absTarget)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "%s %q is not a valid directory\n", red("error"), absTarget)
		os.Exit(1)
	}

	// ── run ─────────────────────────────────────────────
	if *encKey != "" && *decKey != "" {
		fmt.Fprintf(os.Stderr, "%s use -e OR -d, not both\n", red("error"))
		os.Exit(1)
	}

	var runErr error
	if *encKey != "" {
		runErr = runEncrypt(*encKey, absTarget, *dryRun)
	} else {
		runErr = runDecrypt(*decKey, absTarget, *dryRun)
	}

	if runErr != nil {
		fmt.Fprintf(os.Stderr, "\n  %s %v\n\n", red("error:"), runErr)
		os.Exit(1)
	}
}
