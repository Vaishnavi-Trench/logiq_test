FROM python:3.11-alpine

# Set environment variables for NLTK data
ENV NLTK_DATA=/usr/lib/nltk_data

# Install necessary system packages using apk (Alpine package manager)
RUN apk add --no-cache \
    gcc \
    g++ \
    musl-dev \
    libffi-dev \
    bash \
    libsasl \
    openssl-dev \
    librdkafka-dev \
    python3-dev \
    py3-pip \
    libstdc++ \
    && python3 -m ensurepip \
    && pip3 install --upgrade pip setuptools

# Set the working directory inside the container
WORKDIR /usr/lib/trench/modules/logiq

# Copy your Python application code into the container
COPY . /usr/lib/trench/modules/logiq/

# Install Python dependencies globally (you can skip this if venv covers it)
RUN pip install -r requirements.txt

# Set up a virtual environment
RUN python -m venv /usr/lib/trench/envs/logiq-env

# Install requirements inside the virtual environment
RUN /usr/lib/trench/envs/logiq-env/bin/pip install --upgrade pip setuptools && \
    /usr/lib/trench/envs/logiq-env/bin/pip install -r /usr/lib/trench/modules/logiq/requirements.txt

# Download NLTK data (globally and into venv if needed)
RUN pip install nltk && \
    python -c "import nltk; nltk.download('punkt', download_dir='$NLTK_DATA')"

RUN /usr/lib/trench/envs/logiq-env/bin/pip install nltk && \
    /usr/lib/trench/envs/logiq-env/bin/python -c "import nltk; nltk.download('punkt', download_dir='$NLTK_DATA')"

# Copy your script
COPY ./deployment/exec_logiq.sh /usr/lib/trench/modules/logiq/exec_logiq.sh

# Expose a port if needed
EXPOSE 8080

# Use entrypoint
CMD ["/bin/sh", "/usr/lib/trench/modules/logiq/exec_logiq.sh"]


