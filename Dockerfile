FROM golang:alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/clilogin ./cmd/clilogin

FROM alpine:3.20
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app
RUN mkdir -p /app/data && chown -R app:app /app
COPY --from=builder /out/clilogin /app/clilogin
USER app
ENTRYPOINT ["/app/clilogin"]
