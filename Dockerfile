FROM docker

RUN apk add python3 && mkdir /etc/yards

ADD yards.py /usr/bin/yards.py
ENTRYPOINT [ "/usr/bin/yards.py" ]