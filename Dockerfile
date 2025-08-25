# Azure Functions Python (v4) container
# Builds a self-contained image that runs the Function host on port 80

FROM mcr.microsoft.com/azure-functions/python:4-python3.12

# Function host expects code under /home/site/wwwroot
ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true

# Install Python deps first for better layer caching
COPY requirements.txt /requirements.txt
RUN python -m pip install --no-cache-dir -r /requirements.txt

# Copy the function app source
COPY . /home/site/wwwroot

# Expose HTTP (Functions host listens on 80 in this base image)
EXPOSE 80

# Base image provides the entrypoint to start the Functions host
