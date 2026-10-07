FROM golang:1.26.6-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN go build -o server ./cmd/server/main.go
RUN go build -o seed-admin ./cmd/seed-admin/main.go

FROM alpine:latest
WORKDIR /root/


COPY --from=builder /app/server .
COPY --from=builder /app/seed-admin .


COPY --from=builder /app/migrations ./migrations


COPY --from=builder /app/web ./web

EXPOSE 8080
CMD ["./server"]