FROM python:3.10.7-bullseye

RUN apt update
RUN apt install -y smbclient
RUN pip install logfmter prometheus_client

COPY probe.py /monitoring/probe.py
RUN chmod +x /monitoring/probe.py

ENTRYPOINT [ "/monitoring/probe.py" ]
