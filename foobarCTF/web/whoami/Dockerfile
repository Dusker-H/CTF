FROM ubuntu:latest

RUN apt-get update

RUN useradd -s /bin/bash bonk

RUN apt install haproxy -y

RUN apt-get install curl -y

WORKDIR /app

RUN curl -sL https://deb.nodesource.com/setup_12.x | bash -
RUN  apt install nodejs

COPY src /app/
COPY src/haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg

RUN chown -R bonk:bonk /app

RUN npm install

USER bonk

RUN chmod +x start.sh
EXPOSE 80
CMD ./start.sh