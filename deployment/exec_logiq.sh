#!/bin/sh
# wait-for-secrets.sh

# Path to the secret configuration file
SECRET_FILE_PATH="/mnt/secrets/logiq.conf"

# Wait for the nteg.conf file to appear in the shared volume
until [ -f "$SECRET_FILE_PATH" ]; do
  echo "Waiting for logiq.conf..."
  sleep 2
done
echo "Found logiq.conf"

# Check the file size and wait until it has content
until [ -s "$SECRET_FILE_PATH" ]; do
  echo "Waiting for logiq.conf to be populated..."
  sleep 2
done
echo "logiq.conf is populated"

# Check file size and contents before proceeding
ls -lh "$SECRET_FILE_PATH"

# Copy the secret configuration file into a local file for your Python app
cp "$SECRET_FILE_PATH" /usr/lib/trench/modules/logiq/logiq.conf
echo "Copied logiq.conf to local directory"

# Change to the project directory
cd /usr/lib/trench/modules/logiq
echo "Starting the app..."
exec /usr/lib/trench/envs/logiq-env/bin/python -m app.main --file="/usr/lib/trench/modules/logiq/logiq.conf"
