FROM alpine

RUN apk add --no-cache py3-pip
RUN apk add --no-cache curl

WORKDIR /app
COPY ./ .

RUN python3 -m pip install --break-system-packages --no-cache-dir waitress

COPY req.txt .
RUN python3 -m pip install --break-system-packages --no-cache-dir -r req.txt

EXPOSE 5000/tcp

ENTRYPOINT ["waitress-serve"] 
CMD ["--host", "0.0.0.0", "--port", "5000", "--call", "app:createApp"]
