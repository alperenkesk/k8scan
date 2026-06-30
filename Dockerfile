FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X main.version=${VERSION} -s -w" -o k8scan ./cmd/k8scan

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /app/k8scan /k8scan

ENTRYPOINT ["/k8scan"]
