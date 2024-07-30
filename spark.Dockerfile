FROM bitnami/spark:3.5.1

USER root
RUN pip install boto3 pefile sqlalchemy psycopg2-binary
USER 1001
