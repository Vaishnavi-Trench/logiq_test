# Use the official slim Python base image (Python 3.11)
FROM python:3.11-slim

# Install necessary system packages
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    musl-dev \
    libffi-dev \
    bash \
    libsasl2-dev \
    libssl-dev \
    librdkafka-dev \
    && python -m ensurepip \
    && pip install --upgrade pip setuptools \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /usr/lib/trench/modules/logiq

# Copy your Python application code into the container
COPY . /usr/lib/trench/modules/logiq/

# Install Python dependencies from the requirements file
RUN pip install -r requirements.txt

# Set up the virtual environment (same as your service file path)
RUN python -m venv /usr/lib/trench/envs/logiq-env

# Activate the virtual environment and install necessary dependencies inside it
RUN /usr/lib/trench/envs/logiq-env/bin/pip install -r /usr/lib/trench/modules/logiq/requirements.txt

RUN pip install nltk && \
    python -c "import nltk; nltk.download('punkt', download_dir='/usr/lib/nltk_data')"
RUN /usr/lib/trench/envs/logiq-env/bin/pip install nltk && \
    python -c "import nltk; nltk.download('punkt', download_dir='/usr/lib/nltk_data')"

# Copy the exec_nteg.sh script into the container (no need to set executable via RUN)
COPY ./deployment/exec_logiq.sh /usr/lib/trench/modules/logiq/exec_logiq.sh

# Expose any necessary ports if your application requires it (uncomment and modify if needed)
EXPOSE 8080

# Use the entrypoint script to wait for the secrets and start the application
CMD ["/bin/sh", "/usr/lib/trench/modules/logiq/exec_logiq.sh"]
