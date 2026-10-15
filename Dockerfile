FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/vault-tls-demo .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/vault-tls-demo /vault-tls-demo
ENTRYPOINT ["/vault-tls-demo"]
