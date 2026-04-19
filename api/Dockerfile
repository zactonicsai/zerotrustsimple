FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o /api .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /api /api
ENTRYPOINT ["/api"]
