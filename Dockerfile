FROM python:3.11-slim-bullseye
WORKDIR /a
RUN apt update
RUN apt install -y smbclient
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

COPY classes.py /monitoring/classes.py
COPY cli_arg_parse.py /monitoring/cli_arg_parse.py
COPY constants.py /monitoring/constants.py
COPY load_config.py /monitoring/load_config.py
COPY probe.py /monitoring/probe.py
RUN chmod +x /monitoring/probe.py

ENTRYPOINT [ "/monitoring/probe.py" ]
