import os
import logging
import boto3
from botocore.exceptions import ClientError
from typing import Optional
import hashlib
from datetime import datetime

logger = logging.getLogger("R2Storage")

class R2Storage:
    """Cloudflare R2 Storage client using S3-compatible API"""
    
    def __init__(self):
        # R2 Configuration from environment variables
        self.account_id = os.getenv("R2_ACCOUNT_ID")
        self.access_key_id = os.getenv("R2_ACCESS_KEY_ID")
        self.secret_access_key = os.getenv("R2_SECRET_ACCESS_KEY")
        self.bucket_name = os.getenv("R2_BUCKET_NAME", "argus-scripts")
        self.public_url_base = os.getenv("R2_PUBLIC_URL_BASE")  # e.g., https://scripts.example.com
        
        if not all([self.account_id, self.access_key_id, self.secret_access_key]):
            logger.warning("R2 credentials not configured. R2 upload will be disabled.")
            self.client = None
            return
        
        # Create S3 client configured for R2
        self.endpoint_url = f"https://{self.account_id}.r2.cloudflarestorage.com"
        
        try:
            self.client = boto3.client(
                's3',
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.access_key_id,
                aws_secret_access_key=self.secret_access_key,
                region_name='auto'  # R2 uses 'auto' for region
            )
            logger.info(f"R2 client initialized for bucket: {self.bucket_name}")
        except Exception as e:
            logger.error(f"Failed to initialize R2 client: {e}")
            self.client = None
    
    def is_available(self) -> bool:
        """Check if R2 storage is available"""
        return self.client is not None
    
    def generate_object_key(self, filename: str, user_id: str) -> str:
        """
        Generate a unique object key for R2 storage.
        Format: scripts/{user_id}/{year}/{month}/{hash}_{filename}
        """
        now = datetime.utcnow()
        year = now.strftime("%Y")
        month = now.strftime("%m")
        
        # Create a hash of the content + timestamp for uniqueness
        unique_str = f"{user_id}_{filename}_{now.isoformat()}"
        file_hash = hashlib.md5(unique_str.encode()).hexdigest()[:8]
        
        # Clean filename
        safe_filename = "".join(c for c in filename if c.isalnum() or c in ".-_")
        
        return f"scripts/{user_id}/{year}/{month}/{file_hash}_{safe_filename}"
    
    async def upload_script(
        self, 
        content: str, 
        filename: str,
        user_id: str,
        content_type: str = "text/plain"
    ) -> Optional[str]:
        """
        Upload script content to R2 storage.
        
        Args:
            content: The script content as string
            filename: Original filename
            user_id: User ID for organizing files
            content_type: MIME type of the content
            
        Returns:
            Public URL of the uploaded file, or None if upload failed
        """
        if not self.is_available():
            logger.warning("R2 storage not available, skipping upload")
            return None
        
        try:
            # Generate unique object key
            object_key = self.generate_object_key(filename, user_id)
            
            # Upload to R2
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=object_key,
                Body=content.encode('utf-8'),
                ContentType=content_type,
                Metadata={
                    'user_id': user_id,
                    'original_filename': filename,
                    'upload_time': datetime.utcnow().isoformat()
                }
            )
            
            # Generate public URL
            if self.public_url_base:
                public_url = f"{self.public_url_base}/{object_key}"
            else:
                # Fallback to R2 default URL
                public_url = f"{self.endpoint_url}/{self.bucket_name}/{object_key}"
            
            logger.info(f"Successfully uploaded script to R2: {object_key}")
            return public_url
            
        except ClientError as e:
            logger.error(f"Failed to upload to R2: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error during R2 upload: {e}")
            return None
    
    async def upload_bytes(
        self,
        content: bytes,
        object_key: str,
        content_type: str = "application/octet-stream",
    ) -> Optional[str]:
        """
        Upload raw bytes to R2 using a caller-supplied deterministic key.

        Args:
            content: Raw bytes to upload
            object_key: Full R2 object key (e.g. web-ui/{user_id}/{task_id}/bug_report.txt)
            content_type: MIME type of the content

        Returns:
            Public URL of the uploaded object, or None if upload failed
        """
        if not self.is_available():
            logger.warning("R2 storage not available, skipping upload")
            return None

        try:
            self.client.put_object(
                Bucket=self.bucket_name,
                Key=object_key,
                Body=content,
                ContentType=content_type,
            )

            if self.public_url_base:
                public_url = f"{self.public_url_base}/{object_key}"
            else:
                public_url = f"{self.endpoint_url}/{self.bucket_name}/{object_key}"

            logger.info("Uploaded bytes to R2: %s", object_key)
            return public_url

        except ClientError as e:
            logger.error("Failed to upload bytes to R2: %s", e)
            return None
        except Exception as e:
            logger.error("Unexpected error during R2 bytes upload: %s", e)
            return None

    async def download_bytes(self, object_key: str) -> Optional[bytes]:
        """
        Download raw bytes from R2.

        Args:
            object_key: Full R2 object key

        Returns:
            File content as bytes, or None if not found / error
        """
        if not self.is_available():
            return None

        try:
            response = self.client.get_object(
                Bucket=self.bucket_name,
                Key=object_key,
            )
            return response["Body"].read()
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                return None
            logger.error("Failed to download from R2: %s", e)
            return None
        except Exception as e:
            logger.error("Unexpected error during R2 download: %s", e)
            return None

    async def delete_script(self, object_key: str) -> bool:
        """
        Delete a script from R2 storage.
        
        Args:
            object_key: The R2 object key
            
        Returns:
            True if deletion successful, False otherwise
        """
        if not self.is_available():
            return False
        
        try:
            self.client.delete_object(
                Bucket=self.bucket_name,
                Key=object_key
            )
            logger.info(f"Successfully deleted script from R2: {object_key}")
            return True
        except ClientError as e:
            logger.error(f"Failed to delete from R2: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during R2 deletion: {e}")
            return False

# Global R2 storage instance
r2_storage = R2Storage()
