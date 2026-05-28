import os
import logging
import boto3
from botocore.client import Config
from datetime import datetime
import uuid

logger = logging.getLogger("R2Uploader")

class R2Uploader:
    """
    Utility class for uploading files to Cloudflare R2 storage.
    """
    
    def __init__(self):
        """
        Initialize R2 client with credentials from environment variables.
        
        Required environment variables:
        - R2_ACCOUNT_ID: Cloudflare R2 account ID
        - R2_ACCESS_KEY_ID: R2 access key ID
        - R2_SECRET_ACCESS_KEY: R2 secret access key
        - R2_BUCKET_NAME: R2 bucket name (optional, defaults to 'argus-scripts')
        """
        self.account_id = os.getenv("R2_ACCOUNT_ID", "<change-me>")
        self.access_key_id = os.getenv("R2_ACCESS_KEY_ID", "<change-me>")
        self.secret_access_key = os.getenv("R2_SECRET_ACCESS_KEY", "<change-me>")
        self.bucket_name = os.getenv("R2_BUCKET_NAME", "argus-scripts")
        
        # Construct R2 endpoint URL
        self.endpoint_url = f"https://{self.account_id}.r2.cloudflarestorage.com"
        
        # Initialize S3 client configured for R2
        self.s3_client = boto3.client(
            's3',
            endpoint_url=self.endpoint_url,
            aws_access_key_id=self.access_key_id,
            aws_secret_access_key=self.secret_access_key,
            config=Config(signature_version='s3v4'),
            region_name='auto'  # R2 uses 'auto' for region
        )
        
        logger.info(f"R2 Uploader initialized with endpoint: {self.endpoint_url}")
        logger.info(f"Target bucket: {self.bucket_name}")
    
    def upload_script(self, script_content: str, user_id: str = None, filename: str = None) -> str:
        """
        Upload a test script to R2 storage.
        
        Args:
            script_content: The script content as a string
            user_id: User ID for organizing files (optional)
            filename: Custom filename (optional, auto-generated if not provided)
        
        Returns:
            Public URL of the uploaded file
        
        Raises:
            Exception: If upload fails
        """
        try:
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                unique_id = str(uuid.uuid4())[:8]
                filename = f"test_script_{timestamp}_{unique_id}.py"
            
            # Construct object key (path in bucket)
            if user_id:
                object_key = f"scripts/{user_id}/{filename}"
            else:
                object_key = f"scripts/{filename}"
            
            logger.info(f"Uploading script to R2: {object_key}")
            
            # Upload to R2
            self.s3_client.put_object(
                Bucket=self.bucket_name,
                Key=object_key,
                Body=script_content.encode('utf-8'),
                ContentType='text/x-python',
                Metadata={
                    'user_id': user_id or 'anonymous',
                    'upload_time': datetime.now().isoformat()
                }
            )
            
            # Generate presigned URL (valid for 1 hour)
            public_url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': self.bucket_name, 'Key': object_key},
                ExpiresIn=3600
            )
            
            logger.info(f"Script uploaded and presigned successfully")
            return public_url
            
        except Exception as e:
            logger.error(f"Failed to upload script to R2: {e}")
            raise Exception(f"R2 upload failed: {str(e)}")
    
    def delete_script(self, object_key: str) -> bool:
        """
        Delete a script from R2 storage.
        
        Args:
            object_key: The object key (path) in the bucket
        
        Returns:
            True if deletion was successful
        
        Raises:
            Exception: If deletion fails
        """
        try:
            logger.info(f"Deleting script from R2: {object_key}")
            
            self.s3_client.delete_object(
                Bucket=self.bucket_name,
                Key=object_key
            )
            
            logger.info(f"Script deleted successfully: {object_key}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete script from R2: {e}")
            raise Exception(f"R2 deletion failed: {str(e)}")
    
    def list_user_scripts(self, user_id: str) -> list:
        """
        List all scripts for a specific user.
        
        Args:
            user_id: User ID to filter scripts
        
        Returns:
            List of script object keys
        """
        try:
            prefix = f"scripts/{user_id}/"
            logger.info(f"Listing scripts for user: {user_id}")
            
            response = self.s3_client.list_objects_v2(
                Bucket=self.bucket_name,
                Prefix=prefix
            )
            
            if 'Contents' not in response:
                return []
            
            scripts = [obj['Key'] for obj in response['Contents']]
            logger.info(f"Found {len(scripts)} scripts for user {user_id}")
            return scripts
            
        except Exception as e:
            logger.error(f"Failed to list scripts from R2: {e}")
            return []


# Global instance
_r2_uploader = None

def get_r2_uploader() -> R2Uploader:
    """
    Get or create the global R2Uploader instance.
    """
    global _r2_uploader
    if _r2_uploader is None:
        _r2_uploader = R2Uploader()
    return _r2_uploader

