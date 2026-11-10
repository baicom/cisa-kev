FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 KEV_DB=/data/kev_cache.db
RUN useradd -r -u 10001 kev && mkdir /data && chown kev /data
WORKDIR /app
COPY kev.py .
USER kev
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["python3", "/app/kev.py"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
