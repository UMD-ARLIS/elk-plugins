ARG ELASTIC_VERSION

# https://www.docker.elastic.co/
FROM docker.elastic.co/logstash/logstash:${ELASTIC_VERSION}

ADD plugins/ /usr/share/logstash/plugins

RUN logstash-plugin install --no-verify --local /usr/share/logstash/plugins/logstash-filter-keycloak_filter-1.0.gem