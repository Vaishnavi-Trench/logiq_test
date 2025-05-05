"""GCP Tools Module"""

from google.cloud import storage

from pltfrm import Logger2 as Logger


def gcs_list_files(intcid: str, bucket_name: str) -> dict:
    """gcp gcs list files"""
    Logger.debug(f"tool:gcs_list_files:\nListing files in GCS bucket: {bucket_name} for {intcid}\n")
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)
    blobs = bucket.list_blobs()

    file_list = [blob.name for blob in blobs]
    Logger.debug(f"Files in GCS bucket {bucket_name}: {file_list}")
    return {"files": file_list}
