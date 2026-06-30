FROM python:3.13-trixie

RUN apt-get update && apt-get install -y \
    openjdk-21-jdk \
    wget \
    curl \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set up tools
WORKDIR /opt

# Install Astrail
RUN curl -L "https://github.com/rootaux/astrail/releases/download/v0.0.5/astrail-cli.zip" -o astrail-cli.zip && unzip astrail-cli.zip -d /opt && rm astrail-cli.zip

# Install Opengrep
ARG OPENGREP_URL
RUN curl -L "${OPENGREP_URL}" -o /usr/local/bin/opengrep && chmod +x /usr/local/bin/opengrep

# Setup application directory
WORKDIR /home/nika

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir -r requirements.txt

COPY . .

ENV JAVA_HOME="/usr/lib/jvm/java-21-openjdk-amd64"
ENV PATH="${PATH}:/opt/astrail"
ENV PYTHONUNBUFFERED=1
# Entrypoint
ENTRYPOINT ["python3", "main.py"]
