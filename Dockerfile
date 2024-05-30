FROM golang:1.20

WORKDIR /app

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY src/ .

RUN go build -o /notes-app

EXPOSE 8080

CMD [ "/notes-app" ]
