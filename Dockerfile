FROM python:3.14.3-alpine3.23 AS build

RUN apk add gcc libffi-dev musl-dev openssl-dev 
COPY ./requirements.txt.pinned /
RUN pip3 install --break-system-packages -r /requirements.txt.pinned

FROM python:3.14.3-alpine3.23

WORKDIR /srv/factory-registration-ref
ENV PYTHONPATH=/srv/factory-registration-ref
ENV FLASK_APP=registration_ref.app:app
RUN apk add openssl 
COPY --from=build /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages
COPY --from=build /usr/local/bin/gunicorn /usr/bin/
COPY --from=build /usr/local/bin/flask /usr/bin/
COPY ./registration_ref /srv/factory-registration-ref/registration_ref
COPY ./docker_run.sh /

ENTRYPOINT ["/docker_run.sh"]
