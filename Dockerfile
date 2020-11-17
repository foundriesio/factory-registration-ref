FROM alpine AS build

RUN apk add gcc libffi-dev musl-dev openssl-dev python3 py3-pip python3-dev
COPY ./requirements.txt.pinned /
RUN pip3 install -r /requirements.txt.pinned

FROM alpine

WORKDIR /srv/factory-registration-ref
ENV PYTHONPATH=/srv/factory-registration-ref
ENV FLASK_APP=registration_ref.app:app
RUN apk add python3
COPY --from=build /usr/lib/python3.8/site-packages /usr/lib/python3.8/site-packages
COPY --from=build /usr/bin/gunicorn /usr/bin/
COPY --from=build /usr/bin/flask /usr/bin/
COPY ./registration_ref /srv/factory-registration-ref/registration_ref
COPY ./docker_run.sh /

CMD /docker_run.sh
