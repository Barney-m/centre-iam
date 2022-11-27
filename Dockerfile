FROM golang:1.19.2-alpine3.16 AS centre-iam
WORKDIR /root/workdir/centre-iam
COPY . .
RUN export PATH=$PATH:$(go env GOPATH)/bin && \
  go mod tidy && go build -o main main.go

FROM alpine:latest
WORKDIR /root/workdir/centre-iam
COPY --from=centre-iam /root/workdir/centre-iam .

CMD [ "/root/workdir/centre-iam/main" ]