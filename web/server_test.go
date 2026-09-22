package main

import ("net/http"
	"net/http/httptest"
	"testing"
)

// Тест 1: Проверка оценки риска портов
func TestPortRisk(t *testing.T) {
	tests := []struct {
		port     uint16
		expected string
	}{
		{21, "high"},     // FTP
		{23, "high"},     // Telnet
		{25, "high"},     // SMTP
		{445, "medium"},  // SMB
		{3306, "medium"}, // MySQL
		{22, "low"},      // SSH
		{80, "low"},      // HTTP
		{443, "low"},     // HTTPS
		{9999, "low"},    // Неизвестный
	}

	for _, tt := range tests {
		got := portRisk(tt.port)
		if got != tt.expected {
			t.Errorf("portRisk(%d) = %s, ожидалось %s", tt.port, got, tt.expected)
		}
	}
}

// Тест 2: Проверка оценки общего риска
func TestAssessRisk(t *testing.T) {
	// Низкий риск — только безопасные порты
	lowRisk := []Device{
		{IP: "192.168.0.1", Ports: []Port{{Number: 22, Risk: "low"}, {Number: 80, Risk: "low"}}},
	}
	if got := assessRisk(lowRisk); got != "Низкий" {
		t.Errorf("assessRisk(low) = %s, ожидалось Низкий", got)
	}

	// Средний риск — 1-3 опасных порта
	mediumRisk := []Device{
		{IP: "192.168.0.1", Ports: []Port{{Number: 445, Risk: "medium"}}},
	}
	if got := assessRisk(mediumRisk); got != "Средний" {
		t.Errorf("assessRisk(medium) = %s, ожидалось Средний", got)
	}

	// Высокий риск — больше 3 опасных портов
	highRisk := []Device{
		{IP: "192.168.0.1", Ports: []Port{
			{Number: 21, Risk: "high"},
			{Number: 23, Risk: "high"},
			{Number: 25, Risk: "high"},
			{Number: 445, Risk: "medium"},
		}},
	}
	if got := assessRisk(highRisk); got != "Высокий" {
		t.Errorf("assessRisk(high) = %s, ожидалось Высокий", got)
	}
}

// Тест 3: Проверка API-ключа (middleware)
func TestRequireAPIKey(t *testing.T) {
	called := false
	handler := requireAPIKey(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	// Без ключа — обработчик не должен вызваться
	req := httptest.NewRequest("GET", "/api/scan", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if called {
		t.Error("Обработчик вызвался без API-ключа")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Ожидался статус 401, получен %d", rec.Code)
	}

	// С правильным ключом — обработчик вызывается
	called = false
	req = httptest.NewRequest("GET", "/api/scan", nil)
	req.Header.Set("X-API-Key", APIKey)
	rec = httptest.NewRecorder()
	handler(rec, req)

	if !called {
		t.Error("Обработчик не вызвался с правильным API-ключом")
	}
}

// Тест 4: Проверка writeJSON
func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, 200, map[string]string{"hello": "world"})

	if rec.Code != 200 {
		t.Errorf("Ожидался статус 200, получен %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Ожидался Content-Type application/json, получен %s", rec.Header().Get("Content-Type"))
	}
	if rec.Body.String() != "{\"hello\":\"world\"}\n" {
		t.Errorf("Неверное тело ответа: %s", rec.Body.String())
	}
}
