package org.example;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;

import java.net.URI;
import java.time.Duration;

public class S3Manager {
    private static final String BUCKET_NAME = System.getenv().getOrDefault("S3_BUCKET_NAME", "homecloud-vlogger-temp-storage");
    private static final String REGION_NAME = System.getenv().getOrDefault("AWS_REGION", "us-east-1");
    private static final String ENDPOINT = System.getenv().getOrDefault("S3_ENDPOINT", ""); // e.g. https://<account_id>.r2.cloudflarestorage.com
    
    private static S3Client s3Client;
    private static S3Presigner s3Presigner;
    private static boolean isInitialized = false;

    public static synchronized void initialize() {
        if (isInitialized) return;
        
        try {
            Region region = Region.of(REGION_NAME);
            
            S3ClientBuilder clientBuilder = S3Client.builder().region(region);
            S3Presigner.Builder presignerBuilder = S3Presigner.builder().region(region);
            
            // Check for explicit credentials in environment
            String accessKey = System.getenv("AWS_ACCESS_KEY_ID");
            String secretKey = System.getenv("AWS_SECRET_ACCESS_KEY");
            if (accessKey != null && secretKey != null) {
                StaticCredentialsProvider credsProvider = StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(accessKey, secretKey)
                );
                clientBuilder.credentialsProvider(credsProvider);
                presignerBuilder.credentialsProvider(credsProvider);
            }
            
            // If custom endpoint (like Cloudflare R2 or MinIO) is specified
            if (ENDPOINT != null && !ENDPOINT.isEmpty()) {
                URI endpointUri = URI.create(ENDPOINT);
                clientBuilder.endpointOverride(endpointUri);
                presignerBuilder.endpointOverride(endpointUri);
            }
            
            s3Client = clientBuilder.build();
            s3Presigner = presignerBuilder.build();
            isInitialized = true;
            System.out.println("[S3Manager] S3 Client & Presigner initialized successfully.");
            System.out.println("[S3Manager] Region: " + REGION_NAME + ", Bucket: " + BUCKET_NAME + (ENDPOINT.isEmpty() ? "" : ", Endpoint: " + ENDPOINT));
        } catch (Exception e) {
            System.err.println("[S3Manager] Failed to initialize S3 client: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    public static S3Client getS3Client() {
        if (!isInitialized) initialize();
        return s3Client;
    }
    
    public static S3Presigner getS3Presigner() {
        if (!isInitialized) initialize();
        return s3Presigner;
    }
    
    public static String getBucketName() {
        return BUCKET_NAME;
    }

    /**
     * Generates a pre-signed URL for direct upload (PUT)
     * @param objectKey Key of the file in S3 (e.g. user_123/file.mp4)
     * @return Pre-signed URL string
     */
    public static String generatePresignedPutUrl(String objectKey) {
        if (!isInitialized) initialize();
        if (s3Presigner == null) return null;
        
        try {
            PutObjectRequest putRequest = PutObjectRequest.builder()
                    .bucket(BUCKET_NAME)
                    .key(objectKey)
                    .build();
            
            PutObjectPresignRequest presignRequest = PutObjectPresignRequest.builder()
                    .signatureDuration(Duration.ofMinutes(15))
                    .putObjectRequest(putRequest)
                    .build();
            
            PresignedPutObjectRequest presigned = s3Presigner.presignPutObject(presignRequest);
            return presigned.url().toString();
        } catch (Exception e) {
            System.err.println("[S3Manager] Error generating pre-signed PUT URL: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Generates a pre-signed URL for download (GET)
     * @param objectKey Key of the file in S3 (e.g. user_123/file.mp4)
     * @return Pre-signed URL string
     */
    public static String generatePresignedGetUrl(String objectKey) {
        if (!isInitialized) initialize();
        if (s3Presigner == null) return null;
        
        try {
            GetObjectRequest getRequest = GetObjectRequest.builder()
                    .bucket(BUCKET_NAME)
                    .key(objectKey)
                    .build();
            
            GetObjectPresignRequest presignRequest = GetObjectPresignRequest.builder()
                    .signatureDuration(Duration.ofMinutes(15))
                    .getObjectRequest(getRequest)
                    .build();
            
            PresignedGetObjectRequest presigned = s3Presigner.presignGetObject(presignRequest);
            return presigned.url().toString();
        } catch (Exception e) {
            System.err.println("[S3Manager] Error generating pre-signed GET URL: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Deletes an object from the S3 bucket
     * @param objectKey Key of the file in S3 (e.g. user_123/file.mp4)
     */
    public static void deleteObject(String objectKey) {
        if (!isInitialized) initialize();
        if (s3Client == null) return;
        
        try {
            DeleteObjectRequest deleteRequest = DeleteObjectRequest.builder()
                    .bucket(BUCKET_NAME)
                    .key(objectKey)
                    .build();
            s3Client.deleteObject(deleteRequest);
            System.out.println("[S3Manager] Deleted object from S3: " + objectKey);
        } catch (Exception e) {
            System.err.println("[S3Manager] Failed to delete object: " + objectKey + " - " + e.getMessage());
            e.printStackTrace();
        }
    }
}
