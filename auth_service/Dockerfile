FROM python:3.10

WORKDIR /auth_service

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

COPY requirements.txt requirements.txt
COPY wait_for_it.sh wait_for_it.sh

RUN  pip install --upgrade pip \
     && pip install -r requirements.txt \
     && sed $'s/\r$//' ./wait_for_it.sh > ./wait_for_it.unix.sh \
     && chmod +x wait_for_it.unix.sh \
     && flask db init \
     && flask db migrate \
     && flask db upgrade
COPY . .

ENTRYPOINT bash ./wait_for_it.unix.sh $POSTGRES_HOST:$POSTGRES_PORT \
    -- ./wait_for_it.unix.sh $REDIS_HOST:$REDIS_PORT \
    -- gunicorn --worker-class \
    gevent --workers $APP_GEVENT_WORKERS \
    --bind 0.0.0.0:$APP_PORT wsgi_app:app
