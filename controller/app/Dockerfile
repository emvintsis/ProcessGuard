FROM python:3.12-slim

ENV APP=/app
WORKDIR ${APP}

COPY ./main.py .
COPY ./requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8001
USER 1000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]