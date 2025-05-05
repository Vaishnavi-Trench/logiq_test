"""aws tools module."""

from pltfrm import Logger2 as Logger


def aws_s3_list_files(intcid: str, bucket_name: str) -> dict:
    """aws s3 list files"""
    Logger.debug(
        f"tool:aws_s3_list_files:\nListing files in S3 bucket: {bucket_name} for {intcid}\n"
    )
    Logger.debug(f"Files in S3 bucket {bucket_name}")
    return {"files": ["file1.txt", "file2.txt", "file3.txt"]}
