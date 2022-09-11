FROM python:3.7.5

WORKDIR /home/besjan_hf

COPY requirements.txt requirements.txt
RUN python -m venv venv
RUN venv/bin/pip install -r requirements.txt
RUN venv/bin/pip install gunicorn

COPY app app
COPY boot.sh ./
RUN chmod +x boot.sh


EXPOSE 5000

CMD ["./boot.sh"]
