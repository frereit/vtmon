FROM python:3-bookworm

WORKDIR /app

COPY . .

RUN pip install .

ENTRYPOINT [ "vtmon" ]
