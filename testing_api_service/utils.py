import os
import boto3
from dotenv import load_dotenv
from botocore.client import Config
from botocore.exceptions import ClientError
from typing import Optional, List, Dict, Any
from pathlib import Path
import mimetypes
import logging

load_dotenv()

logger = logging.getLogger(__name__)


class CloudflareR2Manager:
    """
    Cloudflare R2 storage manager.

    Provides CRUD operations against Cloudflare R2 object storage, with support
    for publicly accessible file upload and download.

    Environment variables:
        CLOUDFLARE_R2_ACCOUNT_ID: R2 account ID
        CLOUDFLARE_R2_ACCESS_KEY_ID: R2 access key ID
        CLOUDFLARE_R2_SECRET_ACCESS_KEY: R2 secret access key
        CLOUDFLARE_R2_BUCKET_NAME: Bucket name
        CLOUDFLARE_R2_PUBLIC_URL: Public-access domain (e.g. https://pub-xxxx.r2.dev)
    """
    
    def __init__(
        self,
        account_id: Optional[str] = None,
        access_key_id: Optional[str] = None,
        secret_access_key: Optional[str] = None,
        bucket_name: Optional[str] = None,
        public_url: Optional[str] = None
    ):
        """
        Initialize the R2 manager.

        If no arguments are provided, configuration is read from environment variables.
        """
        self.account_id = account_id or os.getenv("CLOUDFLARE_R2_ACCOUNT_ID")
        self.access_key_id = access_key_id or os.getenv("CLOUDFLARE_R2_ACCESS_KEY_ID")
        self.secret_access_key = secret_access_key or os.getenv("CLOUDFLARE_R2_SECRET_ACCESS_KEY")
        self.bucket_name = bucket_name or os.getenv("CLOUDFLARE_R2_BUCKET_NAME")
        self.public_url = public_url or os.getenv("CLOUDFLARE_R2_PUBLIC_URL", "")
        
        if not all([self.account_id, self.access_key_id, self.secret_access_key, self.bucket_name]):
            raise ValueError(
                "Missing required R2 configuration. Please set: "
                "CLOUDFLARE_R2_ACCOUNT_ID, CLOUDFLARE_R2_ACCESS_KEY_ID, "
                "CLOUDFLARE_R2_SECRET_ACCESS_KEY, CLOUDFLARE_R2_BUCKET_NAME"
            )
        
        # R2 endpoint format: https://<account_id>.r2.cloudflarestorage.com
        endpoint_url = f"https://{self.account_id}.r2.cloudflarestorage.com"
        
        # Initialize the S3 client (R2 is S3-API compatible)
        self.s3_client = boto3.client(
            's3',
            endpoint_url=endpoint_url,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            config=Config(signature_version='s3v4'),
            region_name='auto'  # R2 uses 'auto' as the region
        )
        
        logger.info(f"R2 Manager initialized for bucket: {self.bucket_name}")
        
        # Check for and create the bucket if it doesn't exist
        self._ensure_bucket_exists()
    
    def _ensure_bucket_exists(self):
        """
        Ensure the bucket exists; create it if it doesn't.
        """
        if not self.bucket_exists():
            logger.info(f"Bucket {self.bucket_name} does not exist, creating...")
            result = self.create_bucket()
            if result["success"]:
                logger.info(f"Bucket {self.bucket_name} created successfully")
            else:
                logger.warning(f"Failed to create bucket: {result.get('error')}")
        else:
            logger.info(f"Bucket {self.bucket_name} already exists")
    
    def bucket_exists(self) -> bool:
        """
        Check whether the bucket exists.

        Returns:
            Whether the bucket exists.
        """
        try:
            self.s3_client.head_bucket(Bucket=self.bucket_name)
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                return False
            else:
                logger.error(f"Error checking bucket existence: {e}")
                return False
    
    def create_bucket(self) -> Dict[str, Any]:
        """
        Create a new bucket.

        Returns:
            A dict containing the creation result.
        """
        try:
            # R2 does not require LocationConstraint when creating a bucket
            self.s3_client.create_bucket(Bucket=self.bucket_name)
            
            logger.info(f"Bucket created successfully: {self.bucket_name}")
            
            return {
                "success": True,
                "bucket_name": self.bucket_name,
                "message": "Bucket created successfully"
            }
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'BucketAlreadyOwnedByYou':
                logger.info(f"Bucket already exists and is owned by you: {self.bucket_name}")
                return {
                    "success": True,
                    "bucket_name": self.bucket_name,
                    "message": "Bucket already exists"
                }
            else:
                logger.error(f"Failed to create bucket: {e}")
                return {
                    "success": False,
                    "error": str(e)
                }
        except Exception as e:
            logger.error(f"Unexpected error during bucket creation: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def upload_file(
        self, 
        file_path: str, 
        object_key: Optional[str] = None,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Upload a file to the R2 bucket.

        Args:
            file_path: Local file path.
            object_key: Object key in R2 (defaults to the file name if not provided).
            content_type: MIME type (auto-inferred if not provided).
            metadata: Custom metadata.

        Returns:
            A dict containing upload info, including the download URL.
        """
        try:
            # If object_key isn't specified, use the file name
            if not object_key:
                object_key = Path(file_path).name

            # Auto-infer content_type
            if not content_type:
                content_type, _ = mimetypes.guess_type(file_path)
                if not content_type:
                    content_type = 'application/octet-stream'

            # Prepare upload arguments
            extra_args = {
                'ContentType': content_type,
            }

            # Attach metadata
            if metadata:
                extra_args['Metadata'] = metadata

            # Upload the file
            with open(file_path, 'rb') as file:
                self.s3_client.upload_fileobj(
                    file,
                    self.bucket_name,
                    object_key,
                    ExtraArgs=extra_args
                )

            # Build the download URL
            download_url = self.get_public_url(object_key)
            
            logger.info(f"File uploaded successfully: {object_key}")
            
            return {
                "success": True,
                "object_key": object_key,
                "download_url": download_url,
                "bucket": self.bucket_name,
                "content_type": content_type
            }
            
        except ClientError as e:
            logger.error(f"Failed to upload file: {e}")
            return {
                "success": False,
                "error": str(e)
            }
        except Exception as e:
            logger.error(f"Unexpected error during upload: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def upload_file_object(
        self,
        file_obj,
        object_key: str,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Upload a file object (used for API uploads).

        Args:
            file_obj: File object or byte stream.
            object_key: Object key in R2.
            content_type: MIME type.
            metadata: Custom metadata.

        Returns:
            A dict containing upload info.
        """
        try:
            # Prepare upload arguments
            extra_args = {}
            if content_type:
                extra_args['ContentType'] = content_type
            if metadata:
                extra_args['Metadata'] = metadata

            # Upload the file object
            self.s3_client.upload_fileobj(
                file_obj,
                self.bucket_name,
                object_key,
                ExtraArgs=extra_args if extra_args else None
            )

            # Build the download URL
            download_url = self.get_public_url(object_key)
            
            logger.info(f"File object uploaded successfully: {object_key}")
            
            return {
                "success": True,
                "object_key": object_key,
                "download_url": download_url,
                "bucket": self.bucket_name
            }
            
        except ClientError as e:
            logger.error(f"Failed to upload file object: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def download_file(self, object_key: str, local_path: str) -> Dict[str, Any]:
        """
        Download a file from R2 to the local filesystem.

        Args:
            object_key: Object key in R2.
            local_path: Local destination path.

        Returns:
            A dict containing download info.
        """
        try:
            self.s3_client.download_file(self.bucket_name, object_key, local_path)
            
            logger.info(f"File downloaded successfully: {object_key} -> {local_path}")
            
            return {
                "success": True,
                "object_key": object_key,
                "local_path": local_path
            }
            
        except ClientError as e:
            logger.error(f"Failed to download file: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def delete_file(self, object_key: str) -> Dict[str, Any]:
        """
        Delete a file from R2.

        Args:
            object_key: Object key in R2.

        Returns:
            A dict containing the deletion result.
        """
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=object_key)
            
            logger.info(f"File deleted successfully: {object_key}")
            
            return {
                "success": True,
                "object_key": object_key,
                "message": "File deleted successfully"
            }
            
        except ClientError as e:
            logger.error(f"Failed to delete file: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_files(self, prefix: str = "", max_keys: int = 1000) -> Dict[str, Any]:
        """
        List files in the bucket.

        Args:
            prefix: Object key prefix used for filtering.
            max_keys: Maximum number of files to return.

        Returns:
            A dict containing the file list.
        """
        try:
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix,
                MaxKeys=max_keys
            )
            
            files = []
            if 'Contents' in response:
                for obj in response['Contents']:
                    files.append({
                        "key": obj['Key'],
                        "size": obj['Size'],
                        "last_modified": obj['LastModified'].isoformat(),
                        "download_url": self.get_public_url(obj['Key'])
                    })
            
            logger.info(f"Listed {len(files)} files with prefix: {prefix}")
            
            return {
                "success": True,
                "count": len(files),
                "files": files
            }
            
        except ClientError as e:
            logger.error(f"Failed to list files: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_file_info(self, object_key: str) -> Dict[str, Any]:
        """
        Get file information.

        Args:
            object_key: Object key in R2.

        Returns:
            A dict containing file info.
        """
        try:
            response = self.s3_client.head_object(Bucket=self.bucket_name, Key=object_key)
            
            return {
                "success": True,
                "object_key": object_key,
                "size": response['ContentLength'],
                "content_type": response.get('ContentType', 'unknown'),
                "last_modified": response['LastModified'].isoformat(),
                "metadata": response.get('Metadata', {}),
                "download_url": self.get_public_url(object_key)
            }
            
        except ClientError as e:
            if e.response['Error']['Code'] == '404':
                return {
                    "success": False,
                    "error": "File not found"
                }
            logger.error(f"Failed to get file info: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def file_exists(self, object_key: str) -> bool:
        """
        Check whether a file exists.

        Args:
            object_key: Object key in R2.

        Returns:
            Whether the file exists.
        """
        try:
            self.s3_client.head_object(Bucket=self.bucket_name, Key=object_key)
            return True
        except ClientError as e:
            return False
    
    def get_public_url(self, object_key: str) -> str:
        """
        Get the public-access URL for a file.

        Args:
            object_key: Object key in R2.

        Returns:
            Public-access URL.
        """
        if self.public_url:
            # Ensure public_url does not end with '/' and object_key does not start with '/'
            base_url = self.public_url.rstrip('/')
            key = object_key.lstrip('/')
            return f"{base_url}/{key}"
        else:
            # If no public domain is configured, return an informational message
            return f"Public URL not configured. Object key: {object_key}"
    
    def generate_presigned_url(
        self, 
        object_key: str, 
        expiration: int = 3600,
        http_method: str = 'GET'
    ) -> Dict[str, Any]:
        """
        Generate a presigned URL (a temporary access link).

        Args:
            object_key: Object key in R2.
            expiration: URL lifetime in seconds (default: 1 hour).
            http_method: HTTP method ('GET' or 'PUT').

        Returns:
            A dict containing the presigned URL.
        """
        try:
            if http_method == 'GET':
                url = self.s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': self.bucket_name, 'Key': object_key},
                    ExpiresIn=expiration
                )
            elif http_method == 'PUT':
                url = self.s3_client.generate_presigned_url(
                    'put_object',
                    Params={'Bucket': self.bucket_name, 'Key': object_key},
                    ExpiresIn=expiration
                )
            else:
                return {
                    "success": False,
                    "error": "Unsupported HTTP method. Use 'GET' or 'PUT'."
                }
            
            logger.info(f"Generated presigned URL for: {object_key}")
            
            return {
                "success": True,
                "object_key": object_key,
                "presigned_url": url,
                "expiration_seconds": expiration
            }
            
        except ClientError as e:
            logger.error(f"Failed to generate presigned URL: {e}")
            return {
                "success": False,
                "error": str(e)
            }

