package main

import (
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

//go:embed static/index.html
var staticFS embed.FS

const (
	APIVersion = "1.0.0"
	PortsList  = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
)

var (
	APIKey       = getEnv("SCANNER_API_KEY", "dev-key-change-me")
	TargetSubnet = getEnv("SCANNER_SUBNET", "192.168.0.0/24")
	startTime    = time.Now()
)

// getEnv возвращает значение переменной окружения или fallback
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---------- Модели ----------

type Port struct {
	Number  uint16 `json:"number"`
	Service string `json:"service"`
	Risk    string `json:"risk"`
}

type Device struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Ports    []Port `json:"ports"`
}

type Stats struct {
	Devices int     `json:"devices"`
	Ports   int     `json:"ports"`
	Risk    string  `json:"risk"`
	Time    float64 `json:"time"`
	LastRun string  `json:"last_run"`
}

type HistoryEntry struct {
	Time    string `json:"time"`
	Devices int    `json:"devices"`
	Ports   int    `json:"ports"`
	Risk    string `json:"risk"`
}

type Result struct {
	Devices []Device       `json:"devices"`
	Stats   Stats          `json:"stats"`
	Running bool           `json:"running"`
	History []HistoryEntry `json:"history"`
}

var (
	currentResult = Result{}
	mu            sync.Mutex
	scanning      bool
	history       []HistoryEntry
)

// ---------- Логика сканирования ----------

func portRisk(port uint16) string {
	switch port {
	case 21, 23, 25, 110, 143:
		return "high"
	case 445, 3306, 5432, 3389:
		return "medium"
	}
	return "low"
}

func assessRisk(devices []Device) string {
	dangerous := 0
	for _, d := range devices {
		for _, p := range d.Ports {
			if p.Risk == "high" || p.Risk == "medium" {
				dangerous++
			}
		}
	}
	if dangerous == 0 {
		return "Низкий"
	}
	if dangerous <= 3 {
		return "Средний"
	}
	return "Высокий"
}

func runScan() {
	mu.Lock()
	if scanning {
		mu.Unlock()
		return
	}
	scanning = true
	currentResult.Running = true
	mu.Unlock()

	defer func() {
		mu.Lock()
		scanning = false
		currentResult.Running = false
		mu.Unlock()
	}()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(TargetSubnet),
		nmap.WithPorts(PortsList),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
	)
	if err != nil {
		log.Println("Scanner error:", err)
		return
	}

	result, _, err := scanner.Run()
	if err != nil {
		log.Println("Scan error:", err)
		return
	}

	var devices []Device
	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		d := Device{IP: host.Addresses[0].Addr}
		if len(host.Hostnames) > 0 && host.Hostnames[0].Name != "" {
			d.Hostname = host.Hostnames[0].Name
		}
		for _, p := range host.Ports {
			if p.State.State == "open" {
				d.Ports = append(d.Ports, Port{
					Number:  p.ID,
					Service: p.Service.Name,
					Risk:    portRisk(p.ID),
				})
			}
		}
		devices = append(devices, d)
	}

	sort.Slice(devices, func(i, j int) bool {
		return devices[i].IP < devices[j].IP
	})

	totalPorts := 0
	for _, d := range devices {
		totalPorts += len(d.Ports)
	}

	risk := assessRisk(devices)
	now := time.Now().Format("02.01.2006 15:04:05")

	entry := HistoryEntry{
		Time:    now,
		Devices: len(devices),
		Ports:   totalPorts,
		Risk:    risk,
	}

	mu.Lock()
	history = append(history, entry)
	if len(history) > 20 {
		history = history[len(history)-20:]
	}
	currentResult = Result{
		Devices: devices,
		Stats: Stats{
			Devices: len(devices),
			Ports:   totalPorts,
			Risk:    risk,
			Time:    time.Since(start).Seconds(),
			LastRun: now,
		},
		History: history,
	}
	mu.Unlock()

	log.Printf("Сканирование завершено: %d устройств, %d портов, риск: %s",
		len(devices), totalPorts, risk)

	go sendReport()
}

// ---------- Отправка на центральный сервер ----------

func sendReport() {
	mu.Lock()
	if len(currentResult.Devices) == 0 {
		mu.Unlock()
		return
	}
	payload := map[string]interface{}{
		"agent_id":      "scanner-pi",
		"timestamp":     time.Now().Format("02.01.2006 15:04:05"),
		"devices":       currentResult.Devices,
		"devices_count": currentResult.Stats.Devices,
		"ports_count":   currentResult.Stats.Ports,
		"risk":          currentResult.Stats.Risk,
	}
	mu.Unlock()

	body, _ := json.Marshal(payload)
	resp, err := http.Post("http://localhost:9090/api/report",
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		log.Println("Send report error:", err)
		return
	}
	defer resp.Body.Close()
	log.Println("Отчёт отправлен на сервер:", resp.Status)
}

// ---------- Автосканирование ----------

func autoScan() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		log.Println("Автосканирование по расписанию...")
		runScan()
	}
}

// ---------- Системная информация ----------

func systemInfo() map[string]string {
	get := func(cmd string) string {
		out, _ := exec.Command("sh", "-c", cmd).Output()
		return strings.TrimSpace(string(out))
	}
	return map[string]string{
		"ip":   get("hostname -I | awk '{print $1}'"),
		"host": get("hostname"),
		"temp": get("cat /sys/class/thermal/thermal_zone0/temp | awk '{printf \"%.1f\", $1/1000}'"),
		"ram":  get("free -m | awk '/Mem:/ {print $3\"/\"$2\" MB\"}'"),
	}
}

// ---------- Middleware: API-ключ ----------

func requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = r.URL.Query().Get("api_key")
		}
		if key != APIKey {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized","message":"Missing or invalid X-API-Key"}`)
			return
		}
		next(w, r)
	}
}

// ---------- JSON helper ----------

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// ---------- Main ----------

func main() {
	go runScan()
	go autoScan()

	// ----- Главная страница (из static/index.html) -----
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Template not found: "+err.Error(), 500)
			return
		}
		w.Write(data)
	})

	// ----- Публичные эндпоинты -----
	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]interface{}{
			"status":  "ok",
			"service": "network-scanner",
			"version": APIVersion,
			"uptime":  time.Since(startTime).String(),
			"time":    time.Now().Format(time.RFC3339),
		})
	})

	http.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]string{
			"version": APIVersion,
			"name":    "network-scanner",
		})
	})

	http.HandleFunc("/api/results", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, 200, currentResult)
	})

	http.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, systemInfo())
	})

	http.HandleFunc("/api/qr", func(w http.ResponseWriter, r *http.Request) {
		ip := systemInfo()["ip"]
		url := fmt.Sprintf("http://%s:8080", ip)
		cmd := exec.Command("qrencode", "-o", "-", "-t", "PNG", "-s", "6", "-m", "2", url)
		png, err := cmd.Output()
		if err != nil {
			http.Error(w, "QR error: "+err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "no-cache")
		w.Write(png)
	})

	http.HandleFunc("/api/export.csv", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=scan_report.csv")

		writer := csv.NewWriter(w)
		writer.Comma = ';'
		writer.Write([]string{"IP", "Hostname", "Port", "Service", "Risk"})
		for _, d := range currentResult.Devices {
			if len(d.Ports) == 0 {
				writer.Write([]string{d.IP, d.Hostname, "", "", ""})
			}
			for _, p := range d.Ports {
				writer.Write([]string{
					d.IP, d.Hostname,
					fmt.Sprintf("%d", p.Number),
					p.Service, p.Risk,
				})
			}
		}
		writer.Flush()
	})

	// ----- Path-параметр: устройство по IP -----
	http.HandleFunc("/api/device/", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimPrefix(r.URL.Path, "/api/device/")
		if ip == "" {
			writeJSON(w, 400, map[string]string{"error": "IP is required"})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, d := range currentResult.Devices {
			if d.IP == ip {
				writeJSON(w, 200, d)
				return
			}
		}
		writeJSON(w, 404, map[string]string{"error": "device not found", "ip": ip})
	})

	// ----- Фильтрация через query-параметры -----
	http.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		risk := r.URL.Query().Get("risk")
		hasPorts := r.URL.Query().Get("has_ports")
		hostname := r.URL.Query().Get("hostname")

		mu.Lock()
		defer mu.Unlock()

		var filtered []Device
		for _, d := range currentResult.Devices {
			if risk != "" {
				hasRisk := false
				for _, p := range d.Ports {
					if p.Risk == risk {
						hasRisk = true
						break
					}
				}
				if !hasRisk {
					continue
				}
			}
			if hasPorts == "true" && len(d.Ports) == 0 {
				continue
			}
			if hasPorts == "false" && len(d.Ports) > 0 {
				continue
			}
			if hostname != "" && !strings.Contains(strings.ToLower(d.Hostname), strings.ToLower(hostname)) {
				continue
			}
			filtered = append(filtered, d)
		}
		writeJSON(w, 200, map[string]interface{}{
			"count":   len(filtered),
			"devices": filtered,
		})
	})

	// ----- Агрегированная статистика -----
	http.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		riskCounts := map[string]int{"high": 0, "medium": 0, "low": 0}
		portCounts := map[string]int{}
		totalPorts := 0

		for _, d := range currentResult.Devices {
			for _, p := range d.Ports {
				riskCounts[p.Risk]++
				portCounts[p.Service]++
				totalPorts++
			}
		}
		writeJSON(w, 200, map[string]interface{}{
			"total_devices":  len(currentResult.Devices),
			"total_ports":    totalPorts,
			"risk_breakdown": riskCounts,
			"services":       portCounts,
			"history_count":  len(history),
			"uptime":         time.Since(startTime).String(),
		})
	})

	// ----- Защищённые эндпоинты (требуют API-ключ) -----
	http.HandleFunc("/api/scan", requireAPIKey(func(w http.ResponseWriter, r *http.Request) {
		go runScan()
		writeJSON(w, 200, map[string]string{"status": "started"})
	}))

	http.HandleFunc("/api/reports", requireAPIKey(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			mu.Lock()
			history = nil
			currentResult.History = nil
			mu.Unlock()
			writeJSON(w, 200, map[string]string{"status": "cleared"})
			return
		}
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, 200, map[string]interface{}{
			"count":   len(history),
			"history": history,
		})
	}))

	log.Printf("Веб-интерфейс: http://0.0.0.0:8080 (версия %s)", APIVersion)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
