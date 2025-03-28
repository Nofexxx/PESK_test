# Use the official Python image
FROM python:3.12-slim

# Set the working directory
WORKDIR /app

# Copy project source code
COPY . .
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

# Expose the port
EXPOSE 5000

# Run the application
CMD ["flask", "run"]