
FROM python:3.11-slim
WORKDIR /app

# Install system dependencies if required (e.g., build tools or sqlite libraries)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# EXPOSE 8000 (DONT TOUCH , Testing smth)
CMD ["python", "main.py"]