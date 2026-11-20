# Kavach on Google Cloud Run
FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Bake the dashboard styles into the image so the UI never depends on a CDN at demo time
RUN python -c "import urllib.request; urllib.request.urlretrieve('https://cdn.tailwindcss.com', 'web/tailwind.js')" || echo "tailwind download skipped"
EXPOSE 8080
CMD exec uvicorn server.main:app --host 0.0.0.0 --port ${PORT}
