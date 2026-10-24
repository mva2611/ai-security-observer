FROM grafana/grafana:12.4.13
USER root
RUN grafana cli plugins install frser-sqlite-datasource 4.0.6 && \
    mkdir -p /opt/grafana-plugins && \
    mv /var/lib/grafana/plugins/frser-sqlite-datasource /opt/grafana-plugins/
USER 472
