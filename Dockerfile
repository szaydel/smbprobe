FROM python:3.11-slim-bullseye
WORKDIR /a
RUN apt update
RUN apt install -y smbclient

COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

RUN mkdir /monitoring
COPY app /monitoring/app
RUN chmod +x /monitoring/app/main.py

ENTRYPOINT [ "/monitoring/app/main.py" ]
