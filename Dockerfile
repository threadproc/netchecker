FROM golang:1.23 AS build
WORKDIR /src
COPY . /src
RUN CGO_ENABLED=0 GOOS=linux go build -o /netchecker ./cmd/netchecker/

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /netchecker /netchecker
ENV API_ADDR ""
ENV API_USER ""
ENV API_PASS ""
USER nonroot:nonroot
ENTRYPOINT ["/netchecker"]