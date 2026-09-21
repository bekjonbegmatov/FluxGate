FROM haproxy:3.2-alpine
USER root
RUN apk add --no-cache bash
COPY watch.sh /usr/local/bin/watch-haproxy
RUN chmod +x /usr/local/bin/watch-haproxy
CMD ["/usr/local/bin/watch-haproxy"]
