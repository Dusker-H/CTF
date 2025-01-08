FROM ubuntu:20.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends install python3 python3-dev python3-setuptools poppler-utils nginx curl ca-certificates build-essential

RUN curl https://bootstrap.pypa.io/get-pip.py | python3

RUN python3 -m pip install flask python-dotenv uwsgi

RUN useradd -s /bin/bash ubuntu

WORKDIR /home/fileclub/

COPY src/ app

RUN mkdir -p app/uploads
RUN mkdir -p app/extracted

COPY src/nginx.conf src/entrypoint.sh src/req.txt ./

RUN chmod +x entrypoint.sh

RUN chmod a+r -R .

RUN chown ubuntu:ubuntu . app/uploads/ app/extracted/ 

RUN pip install -r req.txt

USER ubuntu

ENTRYPOINT ["./entrypoint.sh"]
