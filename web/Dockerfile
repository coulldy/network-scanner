# --- Этап 1: сборка ---
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Копируем зависимости
COPY go.mod go.sum ./
RUN go mod download

# Копируем код
COPY . .

# Собираем бинарник
RUN CGO_ENABLED=0 GOOS=linux go build -o scanner-web server.go

# --- Этап 2: финальный образ ---
FROM alpine:latest

# Устанавливаем nmap и qrencode
RUN apk add --no-cache nmap qrencode

WORKDIR /app

# Копируем бинарник и статику
COPY --from=builder /app/scanner-web .
COPY --from=builder /app/static ./static

EXPOSE 8080

CMD ["./scanner-web"]
