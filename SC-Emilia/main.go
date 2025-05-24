package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// --- Konfigurasi ---
const (
	ipResolverHost      = "speed.cloudflare.com"
	pathResolver        = "/meta"
	defaultProxyFile    = "Data/ProxyIsp.txt"
	outputFile          = "Data/alive.txt"
	userAgent           = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240"
	requestTimeout      = 10 * time.Second
	maxConcurrentChecks = 50 // Jumlah goroutine maksimum untuk pengecekan proxy
)

// --- Structs ---

// CliArgs untuk menampung argumen command-line
type CliArgs struct {
	InputURL      string
	LocalFilePath string
}

// CloudflareMetaResponse untuk parsing JSON dari Cloudflare
type CloudflareMetaResponse struct {
	ClientIP       string `json:"clientIp"`
	AsOrganization string `json:"asOrganization"`
	Country        string `json:"country"`
}

var nonAlphanumericSpaceRegex = regexp.MustCompile(`[^a-zA-Z0-9\s]`)

func cleanOrgName(orgName string) string {
	if orgName == "" {
		return ""
	}
	return nonAlphanumericSpaceRegex.ReplaceAllString(orgName, "")
}

// fetchIPInfo mengambil informasi IP dari targetURL, bisa melalui proxy
func fetchIPInfo(httpClient *http.Client, targetURL string, proxyURLStr string) (CloudflareMetaResponse, error) {
	var metaResponse CloudflareMetaResponse
	var transport http.Transport

	if proxyURLStr != "" {
		proxyURL, err := url.Parse(proxyURLStr)
		if err != nil {
			return metaResponse, fmt.Errorf("URL proxy tidak valid %s: %w", proxyURLStr, err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Buat client baru dengan transport yang mungkin memiliki proxy
	// atau gunakan client yang sudah ada dan modifikasi transportnya jika memungkinkan
	// Di sini kita buat client per request untuk kesederhanaan pengaturan proxy per request
	// Namun, lebih efisien menggunakan satu client dengan transport yang diubah-ubah atau client pool
	clientWithPossiblyProxy := &http.Client{
		Transport: &transport,
		Timeout:   requestTimeout,
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return metaResponse, fmt.Errorf("gagal membuat request ke %s: %w", targetURL, err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := clientWithPossiblyProxy.Do(req)
	if err != nil {
		return metaResponse, fmt.Errorf("koneksi error ke %s (via proxy: %s): %w", targetURL, proxyURLStr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return metaResponse, fmt.Errorf("request ke %s (via proxy: %s) gagal dengan status: %s", targetURL, proxyURLStr, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return metaResponse, fmt.Errorf("gagal membaca body respons dari %s: %w", targetURL, err)
	}

	err = json.Unmarshal(body, &metaResponse)
	if err != nil {
		// Kadang Cloudflare mengembalikan HTML jika ada masalah, bukan JSON
		// Cetak beberapa byte pertama dari body untuk debug jika JSON gagal parse
		debugBody := string(body)
		if len(debugBody) > 100 {
			debugBody = debugBody[:100]
		}
		return metaResponse, fmt.Errorf("gagal parse JSON dari %s (body: %s...): %w", targetURL, debugBody, err)
	}

	return metaResponse, nil
}

// processProxyLine memproses satu baris proxy
func processProxyLine(
	proxyLine string,
	httpClient *http.Client, // Client HTTP dasar (tanpa proxy)
	cloudflareURL string,
	originalClientIP string,
	resultsChan chan<- string, // Channel untuk mengirim proxy yang aktif
	wg *sync.WaitGroup, // WaitGroup untuk sinkronisasi goroutine
) {
	defer wg.Done() // Pastikan Done dipanggil saat goroutine selesai

	parts := strings.Split(strings.TrimSpace(proxyLine), ",")
	if len(parts) < 2 {
		// log.Printf("Format baris proxy tidak valid (minimal IP,Port): '%s'", proxyLine)
		return
	}

	proxyIP := strings.TrimSpace(parts[0])
	proxyPort := strings.TrimSpace(parts[1])
	countryFromFile := ""
	orgFromFile := ""
	if len(parts) > 2 {
		countryFromFile = strings.TrimSpace(parts[2])
	}
	if len(parts) > 3 {
		orgFromFile = strings.TrimSpace(parts[3])
	}

	if proxyIP == "" || proxyPort == "" {
		// log.Printf("IP atau Port kosong pada baris: '%s'", proxyLine)
		return
	}

	proxyURLStr := fmt.Sprintf("http://%s:%s", proxyIP, proxyPort)

	proxiedInfo, err := fetchIPInfo(httpClient, cloudflareURL, proxyURLStr)
	if err != nil {
		log.Printf("PROXY DEAD (%s:%s): Error saat fetch via proxy: %v", proxyIP, proxyPort, err)
		return
	}

	if proxiedInfo.ClientIP == "" {
		log.Printf("PROXY DEAD (%s:%s): Tidak ada clientIp via proxy.", proxyIP, proxyPort)
		return
	}

	if originalClientIP != proxiedInfo.ClientIP {
		resolvedOrgName := cleanOrgName(proxiedInfo.AsOrganization)
		if resolvedOrgName == "" { // Jika API tidak memberikan org, gunakan dari file
			resolvedOrgName = cleanOrgName(orgFromFile)
		}

		resolvedCountry := proxiedInfo.Country
		if resolvedCountry == "" { // Jika API tidak memberikan negara, gunakan dari file
			resolvedCountry = countryFromFile
		}

		aliveEntry := fmt.Sprintf("%s,%s,%s,%s", proxyIP, proxyPort, resolvedCountry, resolvedOrgName)
		log.Printf("PROXY LIVE: %s", aliveEntry)
		resultsChan <- aliveEntry
	} else {
		log.Printf("PROXY DEAD (%s:%s): IP sama dengan IP asli.", proxyIP, proxyPort)
	}
}

func main() {
	// Parsing argumen command-line
	inputURLFlag := flag.String("i", "", "URL untuk mengambil daftar proxy (format teks: IP,PORT,NEGARA,ORGANISASI per baris)")
	localFileFlag := flag.String("f", defaultProxyFile, "Path ke file proxy lokal")
	flag.Parse()

	args := CliArgs{
		InputURL:      *inputURLFlag,
		LocalFilePath: *localFileFlag,
	}

	// Buat direktori Data jika belum ada
	if err := os.MkdirAll("Data", os.ModePerm); err != nil {
		log.Fatalf("Gagal membuat direktori Data: %v", err)
	}

	// Mengosongkan/membuat file output di awal
	outFile, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Gagal krusial: Tidak bisa membuat/mengosongkan file output %s: %v", outputFile, err)
	}
	outFile.Close() // Tutup segera, akan dibuka lagi nanti untuk append

	log.Println("Pengecekan proxy dimulai...")

	cloudflareURL := fmt.Sprintf("https://%s%s", ipResolverHost, pathResolver)

	// Client HTTP dasar (tanpa proxy khusus di sini, akan diatur per request di fetchIPInfo)
	httpClient := &http.Client{
		Timeout: requestTimeout, // Timeout default untuk client
	}

	// 1. Dapatkan IP asli sekali saja
	log.Println("Mendapatkan IP asli...")
	originalInfo, err := fetchIPInfo(httpClient, cloudflareURL, "") // Proxy string kosong berarti tanpa proxy
	if err != nil {
		log.Fatalf("Gagal mendapatkan IP asli awal: %v. Keluar.", err)
	}
	if originalInfo.ClientIP == "" {
		log.Fatalf("Tidak bisa mendapatkan clientIp asli dari Cloudflare. Keluar.")
	}
	originalClientIP := originalInfo.ClientIP
	log.Printf("IP Asli terdeteksi: %s", originalClientIP)

	var proxyLinesToProcess []string

	// Ambil proxy dari URL jika diberikan
	if args.InputURL != "" {
		log.Printf("Mengambil daftar proxy dari URL (format teks): %s", args.InputURL)
		req, err := http.NewRequest("GET", args.InputURL, nil)
		if err != nil {
			log.Printf("Gagal membuat request ke URL proxy list %s: %v", args.InputURL, err)
		} else {
			req.Header.Set("User-Agent", userAgent) // User agent untuk request proxy list
			resp, err := httpClient.Do(req)
			if err != nil {
				log.Printf("Gagal mengambil data dari URL proxy list %s: %v", args.InputURL, err)
			} else {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					bodyBytes, err := io.ReadAll(resp.Body)
					if err != nil {
						log.Printf("Gagal membaca teks dari respons URL proxy list %s: %v", args.InputURL, err)
					} else {
						textContent := string(bodyBytes)
						lines := strings.Split(textContent, "\n")
						for _, line := range lines {
							trimmedLine := strings.TrimSpace(line)
							if trimmedLine != "" && !strings.HasPrefix(trimmedLine, "#") {
								proxyLinesToProcess = append(proxyLinesToProcess, trimmedLine)
							}
						}
						log.Printf("Ditemukan %d baris proxy dari URL.", len(proxyLinesToProcess))
					}
				} else {
					log.Printf("Request ke URL proxy list %s gagal dengan status: %s", args.InputURL, resp.Status)
				}
			}
		}
	}

	// Jika tidak ada proxy dari URL (baik karena URL tidak diberikan atau gagal), baca dari file
	if len(proxyLinesToProcess) == 0 {
		filePath := args.LocalFilePath
		log.Printf("Membaca proxy dari file lokal: %s", filePath)
		file, err := os.Open(filePath)
		if err != nil {
			if args.InputURL == "" { // Hanya fatal jika file adalah satu-satunya sumber dan gagal
				log.Fatalf("Gagal membuka file proxy %s: %v", filePath, err)
			} else {
				log.Printf("Gagal membuka file proxy %s (setelah URL juga gagal/kosong): %v", filePath, err)
			}
		} else {
			defer file.Close()
			scanner := bufio.NewScanner(file)
			countFromFile := 0
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					proxyLinesToProcess = append(proxyLinesToProcess, line)
					countFromFile++
				}
			}
			if err := scanner.Err(); err != nil {
				log.Printf("Error saat membaca file proxy %s: %v", filePath, err)
			}
			if countFromFile > 0 {
				log.Printf("Ditambahkan %d baris dari file %s.", countFromFile, filePath)
			} else {
				log.Printf("File %s kosong atau hanya berisi komentar/baris kosong.", filePath)
			}
		}
	}

	if len(proxyLinesToProcess) == 0 {
		log.Println("Tidak ada proxy yang akan diproses dari URL maupun file.")
		log.Println("Pengecekan proxy selesai.")
		return
	}
	log.Printf("Total proxy yang akan diproses: %d", len(proxyLinesToProcess))

	resultsChan := make(chan string, len(proxyLinesToProcess)) // Buffered channel
	var wg sync.WaitGroup
	// Semaphore untuk membatasi jumlah goroutine konkuren
	semaphore := make(chan struct{}, maxConcurrentChecks)

	for _, line := range proxyLinesToProcess {
		wg.Add(1)
		semaphore <- struct{}{} // Ambil slot dari semaphore

		go func(proxyL string) { // Kirim line sebagai argumen ke goroutine
			defer func() {
				<-semaphore // Lepaskan slot semaphore
			}()
			processProxyLine(proxyL, httpClient, cloudflareURL, originalClientIP, resultsChan, &wg)
		}(line)
	}

	// Goroutine untuk menutup channel setelah semua worker selesai
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var activeProxies []string
	for res := range resultsChan {
		activeProxies = append(activeProxies, res)
	}

	if len(activeProxies) > 0 {
		// Buka file untuk append
		outFile, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			log.Fatalf("Gagal membuka file output untuk penulisan akhir %s: %v", outputFile, err)
		}
		defer outFile.Close()

		writer := bufio.NewWriter(outFile)
		for _, proxyEntry := range activeProxies {
			_, err := writer.WriteString(proxyEntry + "\n")
			if err != nil {
				log.Printf("Gagal menulis '%s' ke file output: %v", proxyEntry, err)
			}
		}
		err = writer.Flush() // Pastikan semua data tertulis ke disk
		if err != nil {
			log.Printf("Gagal flush file output: %v", err)
		}
		log.Printf("Total %d proxy aktif disimpan ke %s", len(activeProxies), outputFile)
	} else {
		log.Println("Tidak ada proxy aktif yang ditemukan untuk disimpan.")
	}

	log.Println("Pengecekan proxy selesai.")
}
