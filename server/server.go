package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

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

type Payload struct {
	AgentID   string   `json:"agent_id"`
	Timestamp string   `json:"timestamp"`
	Devices   []Device `json:"devices"`
	DevicesN  int      `json:"devices_count"`
	PortsN    int      `json:"ports_count"`
	Risk      string   `json:"risk"`
}

var (
	reports []Payload
	mu      sync.Mutex
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlPage)
	})

	http.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "POST only", 405)
			return
		}

		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "Bad JSON: "+err.Error(), 400)
			return
		}

		mu.Lock()
		reports = append(reports, p)
		if len(reports) > 100 {
			reports = reports[len(reports)-100:]
		}
		mu.Unlock()

		log.Printf("Получен отчёт от %s: %d устройств, %d портов, риск %s",
			p.AgentID, p.DevicesN, p.PortsN, p.Risk)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	http.HandleFunc("/api/reports", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":   len(reports),
			"reports": reports,
		})
	})

	http.HandleFunc("/api/latest", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if len(reports) == 0 {
			fmt.Fprint(w, `{"status":"empty"}`)
			return
		}
		json.NewEncoder(w).Encode(reports[len(reports)-1])
	})

	log.Println("Сервер-приёмник запущен на порту 9090")
	log.Fatal(http.ListenAndServe(":9090", nil))
}

var _ = time.Now

const htmlPage = `<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Central Server — Приёмник отчётов</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0d1117; color: #e6edf3; font-family: -apple-system, system-ui, sans-serif; padding: 20px; }
h1 { color: #58a6ff; font-size: 24px; }
.sub { color: #8b949e; font-size: 13px; margin-bottom: 20px; }
.big { font-size: 48px; font-weight: 700; color: #58a6ff; margin: 20px 0; }
.report { background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 16px; margin-bottom: 12px; }
.report .head { display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 10px; }
.agent { font-family: monospace; color: #3fb950; font-weight: 600; }
.time { color: #8b949e; font-size: 13px; margin-bottom: 8px; }
.risk { padding: 4px 12px; border-radius: 6px; font-size: 13px; }
.risk.Низкий { background: #1d3a2a; color: #3fb950; }
.risk.Средний { background: #4a3a1d; color: #d29922; }
.risk.Высокий { background: #4a1d1d; color: #ff7b72; }
.stats { color: #8b949e; font-size: 14px; margin-bottom: 10px; }
.device { padding: 8px 0; border-top: 1px solid #30363d; font-size: 14px; }
.ip { font-family: monospace; color: #58a6ff; font-weight: 600; }
.host { color: #8b949e; margin-left: 8px; }
.port { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-family: monospace; margin-left: 6px; }
.port.high { background: #4a1d1d; color: #ff7b72; }
.port.medium { background: #4a3a1d; color: #d29922; }
.port.low { background: #1d3a2a; color: #3fb950; }
</style>
</head>
<body>
<h1>Центральный сервер</h1>
<div class="sub">Приём отчётов от сканеров-агентов через Wi-Fi</div>

<div class="big" id="count">0</div>
<div class="sub">отчётов получено</div>

<h2 style="color:#58a6ff;font-size:16px;margin-top:30px;margin-bottom:12px">История отчётов</h2>
<div id="reports"></div>

<script>
async function load() {
  const r = await fetch('/api/reports');
  const d = await r.json();
  document.getElementById('count').textContent = d.count || 0;

  const box = document.getElementById('reports');
  box.innerHTML = '';
  (d.reports || []).slice().reverse().forEach(rep => {
    const el = document.createElement('div');
    el.className = 'report';
    const portsHtml = (rep.devices || []).map(dev => {
      const ports = (dev.ports || []).map(p =>
        '<span class="port ' + p.risk + '">' + p.number + '/' + p.service + '</span>'
      ).join('');
      return '<div class="device"><span class="ip">' + dev.ip + '</span>' +
             (dev.hostname ? '<span class="host">' + dev.hostname + '</span>' : '') +
             ports + '</div>';
    }).join('');
    el.innerHTML =
      '<div class="head"><span class="agent">' + rep.agent_id + '</span>' +
      '<span class="risk ' + rep.risk + '">Риск: ' + rep.risk + '</span></div>' +
      '<div class="time">' + rep.timestamp + '</div>' +
      '<div class="stats">Устройств: ' + rep.devices_count + ', Портов: ' + rep.ports_count + '</div>' +
      portsHtml;
    box.appendChild(el);
  });
}
load();
setInterval(load, 5000);
</script>
</body>
</html>`
